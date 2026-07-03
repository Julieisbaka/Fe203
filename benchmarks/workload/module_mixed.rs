#![allow(dead_code)]

use std::path::PathBuf;

pub enum JobState {
    Queued,
    Running,
    Completed,
    Failed,
}

pub struct Job {
    pub id: u64,
    pub name: String,
    pub state: JobState,
    pub retries: usize,
    pub output_path: PathBuf,
}

pub fn schedule_jobs() -> Vec<Job> {
    let mut jobs = Vec::new();
    for index in 0..250 {
        jobs.push(Job {
            id: index,
            name: format!("job-{index}"),
            state: if index % 4 == 0 {
                JobState::Queued
            } else if index % 4 == 1 {
                JobState::Running
            } else if index % 4 == 2 {
                JobState::Completed
            } else {
                JobState::Failed
            },
            retries: (index % 5) as usize,
            output_path: PathBuf::from(format!("./tmp/jobs/{index}/out.log")),
        });
    }
    jobs
}

pub fn summarize_jobs(jobs: &[Job]) -> String {
    let mut queued = 0usize;
    let mut running = 0usize;
    let mut completed = 0usize;
    let mut failed = 0usize;

    for job in jobs {
        match job.state {
            JobState::Queued => queued += 1,
            JobState::Running => running += 1,
            JobState::Completed => completed += 1,
            JobState::Failed => failed += 1,
        }
    }

    format!(
        "queued={queued} running={running} completed={completed} failed={failed}"
    )
}

pub fn render_large_text_blob() -> String {
    let mut out = String::new();
    for idx in 0..400 {
        out.push_str(&format!(
            "line={idx} token=alpha_{idx} payload=some_repeated_text_for_scanning\n"
        ));
    }
    out
}

pub fn execute_mixed_workload() -> String {
    let jobs = schedule_jobs();
    let summary = summarize_jobs(&jobs);
    let blob = render_large_text_blob();
    format!("{summary}\nblob_len={}\n", blob.len())
}
