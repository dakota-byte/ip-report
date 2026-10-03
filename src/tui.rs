//! Interactive terminal UI for browsing VirusTotal IP reports.

use std::io::{self, Stdout};
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use reqwest::Client;
use serde_json::Value;

use crate::{fetch_all, summarize};

/// One endpoint's result: the endpoint name and either its JSON or an error.
pub(crate) type EndpointResult<'a> = (&'a str, Result<Value>);

/// Application state for the TUI.
struct App<'a> {
    ip: String,
    raw: bool,
    results: Vec<EndpointResult<'a>>,
    list_state: ListState,
    scroll: u16,
    /// Current contents of the search box.
    input: String,
    /// Whether the search box has keyboard focus.
    input_active: bool,
    /// Set when the user submits a new IP; the event loop performs the fetch.
    pending_ip: Option<String>,
    /// True while a search fetch is in flight.
    loading: bool,
}

impl<'a> App<'a> {
    fn new(ip: &str, results: Vec<EndpointResult<'a>>, raw: bool) -> Self {
        let mut list_state = ListState::default();
        if !results.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            ip: ip.to_string(),
            raw,
            results,
            list_state,
            scroll: 0,
            input: String::new(),
            input_active: false,
            pending_ip: None,
            loading: false,
        }
    }

    /// Replace the current results with a freshly fetched set for `ip`.
    fn set_results(&mut self, ip: String, results: Vec<EndpointResult<'a>>) {
        self.ip = ip;
        self.results = results;
        self.scroll = 0;
        if self.results.is_empty() {
            self.list_state.select(None);
        } else {
            self.list_state.select(Some(0));
        }
    }

    fn selected(&self) -> Option<usize> {
        self.list_state.selected()
    }

    fn select_next(&mut self) {
        let len = self.results.len();
        if len == 0 {
            return;
        }
        let next = match self.selected() {
            Some(i) if i + 1 < len => i + 1,
            Some(_) => 0,
            None => 0,
        };
        self.list_state.select(Some(next));
        self.scroll = 0;
    }

    fn select_prev(&mut self) {
        let len = self.results.len();
        if len == 0 {
            return;
        }
        let prev = match self.selected() {
            Some(0) | None => len - 1,
            Some(i) => i - 1,
        };
        self.list_state.select(Some(prev));
        self.scroll = 0;
    }

    fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }

    fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    /// Color for the IP heading, based on the report's analysis stats.
    ///
    /// Red if any engine flagged the IP as malicious, orange if any flagged it
    /// as suspicious, green if it looks clean. Falls back to the default color
    /// when the report is missing or errored.
    fn verdict_color(&self) -> Color {
        let report = self
            .results
            .iter()
            .find(|(name, _)| *name == "report")
            .and_then(|(_, result)| result.as_ref().ok());

        let Some(json) = report else {
            return Color::Reset;
        };
        let stats = &json["data"]["attributes"]["last_analysis_stats"];

        let count = |key: &str| stats[key].as_u64().unwrap_or(0);
        if count("malicious") > 0 {
            Color::Red
        } else if count("suspicious") > 0 {
            Color::Yellow
        } else {
            Color::Green
        }
    }

    /// Build the text shown in the detail pane for the selected endpoint.
    fn detail_text(&self) -> Text<'static> {
        if self.loading {
            return Text::from(format!("Loading {}…", self.ip));
        }
        let Some(idx) = self.selected() else {
            return Text::from("No endpoints loaded.");
        };
        let (name, result) = &self.results[idx];
        match result {
            Ok(json) => {
                if self.raw {
                    match serde_json::to_string_pretty(json) {
                        Ok(pretty) => Text::from(pretty),
                        Err(err) => Text::from(format!("failed to render JSON: {err}")),
                    }
                } else {
                    Text::from(render_summary(name, json))
                }
            }
            Err(err) => Text::from(format!("error fetching {name}: {err:#}")),
        }
    }
}

/// Render a summary into a string by capturing `summarize`'s stdout output.
fn render_summary(name: &str, json: &Value) -> String {
    // `summarize` prints to stdout; for the TUI we want the same content as a
    // string. Re-implement the small amount of formatting here to avoid
    // capturing stdout.
    let mut out = String::new();
    match name {
        "report" => {
            let attrs = &json["data"]["attributes"];
            out.push_str(&format!("reputation: {}\n", attrs["reputation"]));
            out.push_str(&format!("country:    {}\n", attrs["country"]));
            out.push_str(&format!("as_owner:   {}\n", attrs["as_owner"]));
            out.push_str(&format!("asn:        {}\n", attrs["asn"]));
            out.push_str(&format!("network:    {}\n", attrs["network"]));

            if let Some(stats) = attrs["last_analysis_stats"].as_object() {
                out.push_str("last_analysis_stats:\n");
                for (k, v) in stats {
                    out.push_str(&format!("  {k}: {v}\n"));
                }
            }
        }
        _ => match json["data"].as_array() {
            Some(items) if items.is_empty() => out.push_str("(no items)\n"),
            Some(items) => {
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&format!("--- [{i}] ---\n"));
                    out.push_str(&render_item(name, item));
                }
            }
            None => out.push_str("(no data)\n"),
        },
    }
    out
}

/// Render a single item from a list-style endpoint as text.
fn render_item(name: &str, item: &Value) -> String {
    let attrs = &item["attributes"];
    let mut out = String::new();
    match name {
        "comments" => {
            out.push_str(&format!("date:    {}\n", attrs["date"]));
            out.push_str(&format!(
                "votes:   +{} / -{}\n",
                attrs["votes"]["positive"], attrs["votes"]["negative"]
            ));
            out.push_str(&format!("tags:    {}\n", join_array(&attrs["tags"])));
            out.push_str(&format!(
                "text:    {}\n",
                attrs["text"].as_str().unwrap_or("").trim()
            ));
        }
        "resolutions" => {
            out.push_str(&format!("date:    {}\n", attrs["date"]));
            out.push_str(&format!("host:    {}\n", attrs["host_name"]));
            out.push_str(&format!("ip:      {}\n", attrs["ip_address"]));
        }
        "historical_ssl_certificates" => {
            out.push_str(&format!("issuer:  {}\n", attrs["issuer"]["CN"]));
            out.push_str(&format!("subject: {}\n", attrs["subject"]["CN"]));
            out.push_str(&format!(
                "valid:   {} -> {}\n",
                attrs["validity"]["not_before"], attrs["validity"]["not_after"]
            ));
            out.push_str(&format!("serial:  {}\n", attrs["serial_number"]));
        }
        "historical_whois" => {
            out.push_str(&format!("date:    {}\n", attrs["date"]));
            out.push_str(&format!("registrar: {}\n", attrs["registrar"]));
            out.push_str(&format!("netname: {}\n", attrs["netname"]));
            out.push_str(&format!("country: {}\n", attrs["country"]));
            out.push_str(&format!("org:     {}\n", attrs["org"]));
        }
        _ => {
            out.push_str(&serde_json::to_string_pretty(item).unwrap_or_default());
            out.push('\n');
        }
    }
    out
}

/// Join a JSON array of strings with ", ".
fn join_array(value: &Value) -> String {
    value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

/// Run the interactive TUI until the user quits.
pub(crate) async fn run(
    client: &Client,
    api_key: &str,
    ip: &str,
    results: Vec<EndpointResult<'_>>,
    raw: bool,
) -> Result<()> {
    // Keep `summarize` referenced so the shared formatting stays in sync with
    // the CLI path; the TUI uses `render_summary` for string output.
    let _ = summarize;

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;

    let mut app = App::new(ip, results, raw);
    let res = event_loop(&mut terminal, &mut app, client, api_key).await;

    // Always restore the terminal, even if the event loop errored.
    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();

    res
}

async fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App<'_>,
    client: &Client,
    api_key: &str,
) -> Result<()> {
    loop {
        terminal.draw(|frame| draw(frame, app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                // While the search box is focused, keys edit the input.
                if app.input_active {
                    match key.code {
                        KeyCode::Enter => {
                            let ip = app.input.trim().to_string();
                            app.input_active = false;
                            if !ip.is_empty() {
                                app.loading = true;
                                app.pending_ip = Some(ip);
                            }
                        }
                        KeyCode::Esc => {
                            app.input_active = false;
                            app.input.clear();
                        }
                        KeyCode::Backspace => {
                            app.input.pop();
                        }
                        KeyCode::Char(c) => app.input.push(c),
                        _ => {}
                    }
                    continue;
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('/') => {
                        app.input_active = true;
                        app.input.clear();
                    }
                    KeyCode::Down | KeyCode::Char('j') => app.select_next(),
                    KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
                    KeyCode::PageDown | KeyCode::Char('d') => {
                        for _ in 0..10 {
                            app.scroll_down();
                        }
                    }
                    KeyCode::PageUp | KeyCode::Char('u') => {
                        for _ in 0..10 {
                            app.scroll_up();
                        }
                    }
                    _ => {}
                }
            }
        }

        // Perform a pending search fetch outside of the draw/event handling.
        if let Some(ip) = app.pending_ip.take() {
            // Draw once more so the "Loading…" state is visible before we block
            // on the network request.
            terminal.draw(|frame| draw(frame, app))?;
            let results = fetch_all(client, &ip, api_key).await;
            app.set_results(ip, results);
            app.loading = false;
        }
    }
}

fn draw(frame: &mut ratatui::Frame, app: &mut App<'_>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(frame.area());

    draw_search(frame, app, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(32), Constraint::Min(20)])
        .split(chunks[1]);

    draw_list(frame, app, body[0]);
    draw_detail(frame, app, body[1]);
    draw_footer(frame, chunks[2]);
}

fn draw_search(frame: &mut ratatui::Frame, app: &App<'_>, area: Rect) {
    let (title, style) = if app.input_active {
        (
            " Search IP (Enter to fetch, Esc to cancel) ",
            Style::default().fg(Color::Yellow),
        )
    } else {
        (" Search IP (press / to edit) ", Style::default())
    };

    let paragraph = Paragraph::new(app.input.as_str())
        .block(Block::default().borders(Borders::ALL).title(title))
        .style(style);

    frame.render_widget(paragraph, area);
}

fn draw_list(frame: &mut ratatui::Frame, app: &mut App<'_>, area: Rect) {
    let items: Vec<ListItem> = app
        .results
        .iter()
        .map(|(name, result)| {
            let marker = if result.is_ok() { "" } else { " (error)" };
            ListItem::new(format!("{name}{marker}"))
        })
        .collect();

    let title = Line::from(format!(" {} ", app.ip))
        .style(Style::default().fg(app.verdict_color()));

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(title))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut app.list_state);
}

fn draw_detail(frame: &mut ratatui::Frame, app: &App<'_>, area: Rect) {
    let title = if app.loading {
        " loading… ".to_string()
    } else {
        match app.selected() {
            Some(idx) => format!(" {} ", app.results[idx].0),
            None => " detail ".to_string(),
        }
    };

    let paragraph = Paragraph::new(app.detail_text())
        .block(Block::default().borders(Borders::ALL).title(title))
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0));

    frame.render_widget(paragraph, area);
}

fn draw_footer(frame: &mut ratatui::Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(" q ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" quit   "),
        Span::styled(" / ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" search   "),
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" select   "),
        Span::styled(" PgUp/PgDn ", Style::default().fg(Color::Black).bg(Color::DarkGray)),
        Span::raw(" scroll "),
    ]);
    let paragraph = Paragraph::new(line).style(Style::default().fg(Color::Gray));
    frame.render_widget(paragraph, area);
}
