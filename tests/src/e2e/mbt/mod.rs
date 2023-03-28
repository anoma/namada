use color_eyre::eyre::Result;
use eyre::eyre;

type InitReactor<S> = fn(&gjson::Value) -> Result<S>;
type StepReactor<S> = fn(&mut S, &gjson::Value) -> Result<()>;
type InvReactor<S> = fn(&mut S, &gjson::Value) -> Result<bool>;
type InvStateReactor<S> =
    fn(&mut S, &gjson::Value) -> Result<serde_json::Value>;

use color_eyre::owo_colors::OwoColorize;

use std::time::SystemTime;

pub struct Reactor<'a, S> {
    tag_path: &'a str,
    init_reactor: InitReactor<S>,
    step_reactors: std::collections::HashMap<&'a str, StepReactor<S>>,
    inv_reactors: Vec<InvReactor<S>>,
    inv_state_reactors: Vec<InvStateReactor<S>>,
    sequence_reactors: std::collections::HashMap<&'a str, Vec<&'a str>>,
}

impl<'a, S> Reactor<'a, S> {
    pub fn new(tag_path: &'a str, init_reactor: InitReactor<S>) -> Self {
        Self {
            tag_path,
            init_reactor,
            step_reactors: Default::default(),
            inv_reactors: Default::default(),
            inv_state_reactors: Default::default(),
            sequence_reactors: Default::default(),
        }
    }
}

impl<'a, S> Reactor<'a, S> {
    pub fn register<'b>(&mut self, tag: &'b str, func: StepReactor<S>)
    where
        'b: 'a,
    {
        self.step_reactors.insert(tag, func);
    }

    pub fn register_sequence<'b>(&mut self, tag: &'b str, tags: Vec<&'b str>)
    where
        'b: 'a,
    {
        for t in &tags {
            assert!(self.step_reactors.contains_key(t))
        }

        self.sequence_reactors.insert(tag, tags);
    }

    pub fn register_invariant<'b>(&mut self, func: InvReactor<S>)
    where
        'b: 'a,
    {
        self.inv_reactors.push(func);
    }

    pub fn register_invariant_state<'b>(&mut self, func: InvStateReactor<S>)
    where
        'b: 'a,
    {
        self.inv_state_reactors.push(func);
    }

    fn execute(
        &self,
        system: &mut S,
        tag: &str,
        state: &gjson::Value,
    ) -> Result<()> {
        if let Some(f) = self.step_reactors.get(tag) {
            f(system, state)
        } else if let Some(tags) = self.sequence_reactors.get(tag) {
            for t in tags {
                self.execute(system, t, state)?
            }
            Ok(())
        } else {
            Err(eyre!(format!("tag: {} is not registered.", tag)))
        }
    }

    pub fn test(&self, states: &[gjson::Value]) -> Result<()> {
        let mut inv_states = vec![];
        let time = SystemTime::now();

        fn mbt_log(
            time: SystemTime,
            index: usize,
            tag: &str,
            data: &str,
        ) -> Result<()> {
            println!(
                "[{} {: >4}s] {: >4}:{: <10}> {}",
                "MBT".bright_blue(),
                time.elapsed()?.as_secs().green(),
                index,
                tag.yellow(),
                data
            );
            Ok(())
        }

        let mut system = states
            .first()
            .ok_or_else(|| eyre!("trace is empty"))
            .and_then(|f_state| {
                let mut system = (self.init_reactor)(&f_state)?;
                for inv in self.inv_reactors.iter() {
                    assert!(inv(&mut system, f_state)?);
                }
                for inv_st in self.inv_state_reactors.iter() {
                    inv_states.push(inv_st(&mut system, f_state)?);
                }

                Ok(system)
            })?;
        for (i_state, e_state) in states.iter().enumerate().skip(1) {
            let tag = e_state.get(self.tag_path);
            mbt_log(time, i_state, tag.str(), "Executing Step")?;
            self.execute(&mut system, tag.str(), e_state)?;
            for inv in self.inv_reactors.iter() {
                mbt_log(time, i_state, tag.str(), "Executing Inv")?;
                inv(&mut system, e_state)?;
            }

            for (inv_st, st) in
                self.inv_state_reactors.iter().zip(inv_states.iter())
            {
                mbt_log(time, i_state, tag.str(), "Executing Inv Step")?;
                assert_eq!(st, &inv_st(&mut system, e_state)?);
            }
        }
        Ok(())
    }
}
