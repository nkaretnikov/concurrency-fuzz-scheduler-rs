// Builds a simple schedule diagram from the run/sleep log lines, ported from
// DiagramHelper.java. Events are grouped per task and serialized to the JSON
// shape the original visualization expects.

use std::collections::BTreeMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Running,
    Sleeping,
}

impl EventType {
    fn as_str(&self) -> &'static str {
        match self {
            EventType::Running => "running",
            EventType::Sleeping => "sleeping",
        }
    }
}

struct Event {
    time: f64,
    task: String,
    event_type: EventType,
    duration: f64,
}

#[derive(Default)]
pub struct DiagramHelper {
    events: Vec<Event>,
}

impl DiagramHelper {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_event(&mut self, time_seconds: f64, task: &str, event_type: EventType, duration_seconds: f64) {
        self.events.push(Event {
            time: time_seconds,
            task: task.to_string(),
            event_type,
            duration: duration_seconds,
        });
    }

    /// Serialize the recorded events into the JSON array of per task tracks.
    ///
    /// Kept for parity with the original DiagramHelper. The driver records
    /// events but, like the Java version, does not currently dump the JSON.
    #[allow(dead_code)]
    pub fn create_data_json(&self) -> String {
        // BTreeMap keeps a stable task order, which keeps the output
        // deterministic across runs.
        let mut events_by_task: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
        for event in &self.events {
            events_by_task.entry(&event.task).or_default().push(event);
        }

        let mut json = String::from("[");
        for (i, (task, events)) in events_by_task.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            json.push_str(&format!("{{ \"task\": \"{task}\", \"events\": ["));
            for (j, event) in events.iter().enumerate() {
                if j > 0 {
                    json.push(',');
                }
                json.push_str(&single_event_json(event));
            }
            json.push_str("] }");
        }
        json.push(']');
        json
    }
}

fn single_event_json(event: &Event) -> String {
    format!(
        "{{ \"action\": \"{}\", \"start\": {:.6}, \"duration\": {:.6} }}",
        event.event_type.as_str(),
        event.time,
        event.duration
    )
}
