use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::*,
};
use std::io::stdout;
use std::time::{Duration, Instant};

struct Source {
    name: String,
    path: String,
    entropy: f64,
    files: usize,
    status: &'static str,
    last_scan: String,
    history: Vec<f64>,
}

struct App {
    sources: Vec<Source>,
    selected: usize,
    alerts: Vec<String>,
    tick: u64,
}

impl App {
    fn new() -> Self {
        App {
            sources: vec![
                Source {
                    name: "cthonian".into(),
                    path: "/home".into(),
                    entropy: 4.85,
                    files: 67197,
                    status: "✅ OK",
                    last_scan: "2m ago".into(),
                    history: vec![4.82, 4.83, 4.85, 4.84, 4.85, 4.83, 4.84, 4.85, 4.86, 4.85,
                                  4.84, 4.85, 4.83, 4.85, 4.84, 4.85, 4.86, 4.85, 4.84, 4.85],
                },
                Source {
                    name: "yogsothoth".into(),
                    path: "wdp10".into(),
                    entropy: 7.96,
                    files: 295,
                    status: "✅ OK",
                    last_scan: "5m ago".into(),
                    history: vec![7.95, 7.96, 7.96, 7.95, 7.96, 7.96, 7.95, 7.96, 7.96, 7.95,
                                  7.96, 7.96, 7.95, 7.96, 7.96, 7.95, 7.96, 7.96, 7.95, 7.96],
                },
                Source {
                    name: "yogsothoth".into(),
                    path: "clawd-backup".into(),
                    entropy: 4.85,
                    files: 66991,
                    status: "✅ OK",
                    last_scan: "5m ago".into(),
                    history: vec![4.84, 4.85, 4.85, 4.84, 4.85, 4.85, 4.84, 4.85, 4.85, 4.84,
                                  4.85, 4.85, 4.84, 4.85, 4.85, 4.84, 4.85, 4.85, 4.84, 4.85],
                },
                Source {
                    name: "gertrude".into(),
                    path: "/home".into(),
                    entropy: 5.04,
                    files: 146,
                    status: "✅ OK",
                    last_scan: "8m ago".into(),
                    history: vec![5.02, 5.03, 5.04, 5.03, 5.04, 5.03, 5.04, 5.04, 5.03, 5.04,
                                  5.03, 5.04, 5.04, 5.03, 5.04, 5.03, 5.04, 5.04, 5.03, 5.04],
                },
            ],
            selected: 0,
            alerts: vec!["No alerts. The Watchtower sees all is well.".into()],
            tick: 0,
        }
    }

    fn simulate_tick(&mut self) {
        self.tick += 1;
        // Each source gets unique jitter pattern
        for (i, source) in self.sources.iter_mut().enumerate() {
            let base = source.entropy;
            let phase = (i as f64) * 1.7; // phase offset per source
            let freq = 0.08 + (i as f64) * 0.03; // different frequencies
            let jitter = ((self.tick as f64 * freq + phase).sin() * 0.08) + 
                         ((self.tick as f64 * freq * 2.3 + phase).cos() * 0.04);
            let new_val = base + jitter;
            source.history.push(new_val);
            if source.history.len() > 60 {
                source.history.remove(0);
            }
        }
    }
}

fn render_ui(frame: &mut Frame, app: &App) {
    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Title
            Constraint::Length(8),  // Sources table
            Constraint::Min(10),   // Graph
            Constraint::Length(5), // Alerts
            Constraint::Length(3), // Disk + footer
        ])
        .split(frame.area());

    // Title bar
    let title_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title_alignment(Alignment::Center);
    
    let spinning = match app.tick % 4 {
        0 => "◐",
        1 => "◓",
        2 => "◑",
        _ => "◒",
    };
    
    let title = Paragraph::new(Line::from(vec![
        Span::styled("  🦉 ", Style::default()),
        Span::styled("EXARP", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(" v0.1.0 — Watchtower Active  ", Style::default()),
        Span::styled(spinning, Style::default().fg(Color::Green)),
        Span::styled(" ONLINE", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    ]))
    .block(title_block);
    frame.render_widget(title, main_layout[0]);

    // Sources table
    let header = Row::new(vec!["SOURCE", "PATH", "ENTROPY", "FILES", "STATUS", "LAST"])
        .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .bottom_margin(0);

    let rows: Vec<Row> = app.sources.iter().enumerate().map(|(i, s)| {
        let style = if i == app.selected {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        
        let entropy_style = if s.entropy > 7.5 {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::Green)
        };

        Row::new(vec![
            Cell::from(s.name.clone()).style(style),
            Cell::from(s.path.clone()).style(style),
            Cell::from(format!("{:.2} b/B", s.entropy)).style(entropy_style),
            Cell::from(format!("{:>6}", s.files)).style(style),
            Cell::from(s.status),
            Cell::from(s.last_scan.clone()).style(Style::default().fg(Color::DarkGray)),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(14),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Sources "),
    );
    frame.render_widget(table, main_layout[1]);

    // Entropy graph — ALL sources overlaid
    let colors = [Color::Cyan, Color::Yellow, Color::Green, Color::Magenta, Color::Red, Color::Blue];
    
    let all_data: Vec<Vec<(f64, f64)>> = app.sources.iter().map(|s| {
        s.history.iter().enumerate().map(|(i, &v)| (i as f64, v)).collect()
    }).collect();
    
    let datasets: Vec<Dataset> = app.sources.iter().enumerate().map(|(i, s)| {
        let color = colors[i % colors.len()];
        let marker = if i == app.selected {
            symbols::Marker::Braille
        } else {
            symbols::Marker::Dot
        };
        Dataset::default()
            .name(format!("{} {}", s.name, s.path))
            .marker(marker)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(color))
            .data(&all_data[i])
    }).collect();

    // Y-axis spans ALL sources so you see relative positions
    let y_min = app.sources.iter()
        .flat_map(|s| s.history.iter().cloned())
        .fold(f64::MAX, f64::min) - 0.5;
    let y_max = app.sources.iter()
        .flat_map(|s| s.history.iter().cloned())
        .fold(f64::MIN, f64::max) + 0.5;

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Entropy Timeline — All Sources "),
        )
        .x_axis(
            Axis::default()
                .title("time")
                .style(Style::default().fg(Color::DarkGray))
                .bounds([0.0, 60.0])
                .labels(vec!["60m".to_string(), "30m".to_string(), "now".to_string()]),
        )
        .y_axis(
            Axis::default()
                .title("bits/byte")
                .style(Style::default().fg(Color::DarkGray))
                .bounds([y_min, y_max])
                .labels(vec![
                    format!("{:.1}", y_min),
                    format!("{:.1}", (y_min + y_max) / 2.0),
                    format!("{:.1}", y_max),
                ]),
        );
    frame.render_widget(chart, main_layout[2]);

    // Alerts
    let alert_text: Vec<Line> = app.alerts.iter().map(|a| {
        Line::from(Span::styled(
            format!("  {}", a),
            Style::default().fg(Color::Green),
        ))
    }).collect();

    let alerts = Paragraph::new(alert_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
                .title(" Alerts "),
        );
    frame.render_widget(alerts, main_layout[3]);

    // Footer with disk bars and help
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(" wdp10 ", Style::default().fg(Color::Yellow)),
        Span::styled("█", Style::default().fg(Color::Green)),
        Span::styled("░░░░░░░░░░░░░░░░░░░", Style::default().fg(Color::DarkGray)),
        Span::styled(" 1%  ", Style::default().fg(Color::Green)),
        Span::styled("│ ", Style::default().fg(Color::Cyan)),
        Span::styled("↑↓", Style::default().fg(Color::Yellow)),
        Span::styled(" select  ", Style::default()),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::styled(" quit  ", Style::default()),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::styled(" rescan", Style::default()),
    ]))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(footer, main_layout[4]);
}

pub fn run_dashboard() -> Result<()> {
    enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut app = App::new();
    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|frame| render_ui(frame, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.selected > 0 {
                                app.selected -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.selected < app.sources.len() - 1 {
                                app.selected += 1;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            app.simulate_tick();
            last_tick = Instant::now();
        }
    }

    disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
