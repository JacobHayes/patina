//! Seeded cooperative task scheduling.

use std::collections::BTreeMap;

use patina_abi::{EffectError, ErrorCode, TaskId};
use patina_driver_api::{DriverResult, SchedulerDriver};
use patina_rng_seeded::SplitMix64;

#[derive(Clone, Debug, PartialEq, Eq)]
enum TaskState {
    Runnable,
    Running,
    Parked(String),
}

/// A scheduler that chooses one runnable task from a stable, sorted set.
pub struct DetScheduler {
    generator: SplitMix64,
    tasks: BTreeMap<TaskId, TaskState>,
    next_task: u64,
}

impl DetScheduler {
    pub fn new(seed: u64) -> Self {
        Self {
            generator: SplitMix64::new(seed),
            tasks: BTreeMap::new(),
            next_task: 1,
        }
    }

    pub fn runnable(&self) -> Vec<TaskId> {
        self.tasks
            .iter()
            .filter_map(|(task, state)| (state == &TaskState::Runnable).then_some(*task))
            .collect()
    }

    fn state_mut(&mut self, task: TaskId) -> DriverResult<&mut TaskState> {
        self.tasks.get_mut(&task).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                format!("scheduler task {} does not exist", task.0),
            )
        })
    }
}

impl SchedulerDriver for DetScheduler {
    fn spawn(&mut self, _label: &str) -> DriverResult<TaskId> {
        let task = TaskId(self.next_task);
        self.next_task = self.next_task.checked_add(1).ok_or_else(|| {
            EffectError::new(
                ErrorCode::InvalidHandle,
                "scheduler task identifiers exhausted",
            )
        })?;
        self.tasks.insert(task, TaskState::Runnable);
        Ok(task)
    }

    fn yield_task(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "yield", state));
        }
        *state = TaskState::Runnable;
        Ok(())
    }

    fn park(&mut self, task: TaskId, reason: &str) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "park", state));
        }
        *state = TaskState::Parked(reason.into());
        Ok(())
    }

    fn wake(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if !matches!(state, TaskState::Parked(_)) {
            return Err(invalid_transition(task, "wake", state));
        }
        *state = TaskState::Runnable;
        Ok(())
    }

    fn complete(&mut self, task: TaskId) -> DriverResult<()> {
        let state = self.state_mut(task)?;
        if state != &TaskState::Running {
            return Err(invalid_transition(task, "complete", state));
        }
        self.tasks.remove(&task);
        Ok(())
    }

    fn next(&mut self) -> DriverResult<Option<TaskId>> {
        if let Some((task, _)) = self
            .tasks
            .iter()
            .find(|(_, state)| matches!(state, TaskState::Running))
        {
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                format!(
                    "task {} is still running; yield, park, or complete it before scheduling",
                    task.0
                ),
            ));
        }
        let runnable = self.runnable();
        if runnable.is_empty() {
            if self.tasks.is_empty() {
                return Ok(None);
            }
            let parked = self
                .tasks
                .iter()
                .filter_map(|(task, state)| match state {
                    TaskState::Parked(reason) => Some(format!("{} ({reason})", task.0)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            return Err(EffectError::new(
                ErrorCode::Deadlock,
                format!("no runnable tasks; parked tasks: {}", parked.join(", ")),
            ));
        }
        let index = (self.generator.next_u64() % runnable.len() as u64) as usize;
        let selected = runnable[index];
        self.select(Some(selected))?;
        Ok(Some(selected))
    }

    fn select(&mut self, task: Option<TaskId>) -> DriverResult<()> {
        let Some(task) = task else {
            if self.tasks.is_empty() {
                return Ok(());
            }
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                "cannot select no task while scheduler tasks still exist",
            ));
        };
        if self
            .tasks
            .values()
            .any(|state| matches!(state, TaskState::Running))
        {
            return Err(EffectError::new(
                ErrorCode::InvalidState,
                "cannot select a task while another task is running",
            ));
        }
        let state = self.state_mut(task)?;
        if state != &TaskState::Runnable {
            return Err(invalid_transition(task, "select", state));
        }
        *state = TaskState::Running;
        Ok(())
    }
}

fn invalid_transition(task: TaskId, action: &str, state: &TaskState) -> EffectError {
    EffectError::new(
        ErrorCode::InvalidState,
        format!(
            "cannot {action} scheduler task {} in state {state:?}",
            task.0
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(seed: u64, rounds: usize) -> Vec<TaskId> {
        let mut scheduler = DetScheduler::new(seed);
        for label in ["a", "b", "c"] {
            scheduler.spawn(label).unwrap();
        }
        let mut selected = Vec::new();
        for _ in 0..rounds {
            let task = scheduler.next().unwrap().unwrap();
            selected.push(task);
            scheduler.yield_task(task).unwrap();
        }
        selected
    }

    #[test]
    fn scheduler_has_a_known_seeded_sequence() {
        assert_eq!(
            schedule(7, 8),
            [
                TaskId(1),
                TaskId(1),
                TaskId(1),
                TaskId(1),
                TaskId(2),
                TaskId(1),
                TaskId(2),
                TaskId(1),
            ]
        );
    }

    #[test]
    fn a_thousand_seeds_repeat_schedules_with_park_and_wake() {
        fn with_park_and_wake(seed: u64) -> Vec<TaskId> {
            let mut scheduler = DetScheduler::new(seed);
            for label in ["a", "b", "c"] {
                scheduler.spawn(label).unwrap();
            }
            let parked = scheduler.next().unwrap().unwrap();
            scheduler.park(parked, "blocked").unwrap();
            let running = scheduler.next().unwrap().unwrap();
            scheduler.yield_task(running).unwrap();
            scheduler.wake(parked).unwrap();
            let mut selected = vec![parked, running];
            for _ in 0..20 {
                let task = scheduler.next().unwrap().unwrap();
                selected.push(task);
                scheduler.yield_task(task).unwrap();
            }
            selected
        }

        for seed in 0..1_000 {
            assert_eq!(
                with_park_and_wake(seed),
                with_park_and_wake(seed),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn park_wake_deadlock_and_completion_are_explicit() {
        let mut scheduler = DetScheduler::new(1);
        let task = scheduler.spawn("worker").unwrap();
        assert_eq!(scheduler.next().unwrap(), Some(task));
        scheduler.park(task, "waiting for packet").unwrap();
        let deadlock = scheduler.next().unwrap_err();
        assert_eq!(deadlock.code, ErrorCode::Deadlock);
        assert!(deadlock.message.contains("waiting for packet"));

        scheduler.wake(task).unwrap();
        assert_eq!(scheduler.next().unwrap(), Some(task));
        scheduler.complete(task).unwrap();
        assert_eq!(scheduler.next().unwrap(), None);
    }
}
