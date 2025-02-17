//! A helper to generate automation rules JSON for Speculos emulator of Ledger
//! hardware wallet.
//!
//! Because the JSON format is very verbose, it's not practical to write it by
//! hand. The `Steps` is used to describe the automation in simpler way.
//!
//! To find the necessary steps for a specific test, run it with Speculos (see
//! `genesis/hardware/README.md` for details) with arg `--log-level
//! automation:DEBUG` which will make it log the text appearing on the device
//! screen. E.g.:
//!
//!   automation: getting actions for "Please" (46, 29)
//!   automation: getting actions for "review" (45, 43)

use serde::Serialize;
use serde_tuple::Serialize_tuple;

/// The seed used to generate `genesis/hardware`
pub const SEED: &str =
    "equip will roof matter pink blind book anxiety banner elbow sun young";

const ENV_VAR_NAMADA_DEVICE_AUTOMATION: &str = "NAMADA_DEVICE_AUTOMATION";

// Speculos automation variables
const BUTTON_NUM_LEFT: u8 = 1;
const BUTTON_NUM_RIGHT: u8 = 2;

pub fn uses_automation() -> bool {
    if let Ok(val) = std::env::var(ENV_VAR_NAMADA_DEVICE_AUTOMATION) {
        return val.trim().to_ascii_lowercase() == "true";
    }
    false
}

// Generate automation file for `e2e::ledger_tests::pos_bonds`
pub fn gen_automation_e2e_pos_bonds() -> Automation {
    let steps: Steps = [
        // _____________________________________________________________________
        // 1. tx - delegation bond to validator-0
        please_review_steps(),
        vec![
            Step::Expect {
                text: Text("Type"),
                action: None,
            },
            Step::Expect {
                text: Text("Bond"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Source"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Validator"),
            action: None,
        }],
        address_steps(),
        vec![
            Step::Expect {
                text: Text("Amount"),
                action: None,
            },
            Step::Expect {
                text: Text("NAM 5000.0"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        fee_steps(),
        vec![Step::Expect {
            text: Text("APPROVE"),
            action: Some(PressAndRelease(Button::Both)),
        }],
        // _____________________________________________________________________
        // 2. tx - partial redelegation from validator-0 to validator-1
        please_review_steps(),
        vec![
            Step::Expect {
                text: Text("Type"),
                action: None,
            },
            Step::Expect {
                text: Text("Redelegate"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Source Validator"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Destination Validator"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Owner"),
            action: None,
        }],
        address_steps(),
        vec![
            Step::Expect {
                text: Text("Amount"),
                action: None,
            },
            Step::Expect {
                text: Text("2500.0"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        fee_steps(),
        vec![Step::Expect {
            text: Text("APPROVE"),
            action: Some(PressAndRelease(Button::Both)),
        }],
        // _____________________________________________________________________
        // 3. tx - unbond delegation to validator-0
        please_review_steps(),
        vec![
            Step::Expect {
                text: Text("Type"),
                action: None,
            },
            Step::Expect {
                text: Text("Unbond"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Source"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Validator"),
            action: None,
        }],
        address_steps(),
        vec![
            Step::Expect {
                text: Text("Amount"),
                action: None,
            },
            Step::Expect {
                text: Text("NAM 1600.0"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        fee_steps(),
        vec![Step::Expect {
            text: Text("APPROVE"),
            action: Some(PressAndRelease(Button::Both)),
        }],
        // _____________________________________________________________________
        // 4. tx - unbond delegation to validator-1
        please_review_steps(),
        vec![
            Step::Expect {
                text: Text("Type"),
                action: None,
            },
            Step::Expect {
                text: Text("Unbond"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Source"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Validator"),
            action: None,
        }],
        address_steps(),
        vec![
            Step::Expect {
                text: Text("Amount"),
                action: None,
            },
            Step::Expect {
                text: Text("NAM 1600.0"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        fee_steps(),
        vec![Step::Expect {
            text: Text("APPROVE"),
            action: Some(PressAndRelease(Button::Both)),
        }],
        // _____________________________________________________________________
        // 5. tx - withdraw unbonded delegation to validator-0
        please_review_steps(),
        vec![
            Step::Expect {
                text: Text("Type"),
                action: None,
            },
            Step::Expect {
                text: Text("Withdraw"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Source"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Validator"),
            action: None,
        }],
        address_steps(),
        fee_steps(),
        vec![Step::Expect {
            text: Text("APPROVE"),
            action: Some(PressAndRelease(Button::Both)),
        }],
        // _____________________________________________________________________
        // 6. tx - withdraw unbonded delegation to validator-1
        please_review_steps(),
        vec![
            Step::Expect {
                text: Text("Type"),
                action: None,
            },
            Step::Expect {
                text: Text("Withdraw"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Source"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Validator"),
            action: None,
        }],
        address_steps(),
        fee_steps(),
        vec![Step::Expect {
            text: Text("APPROVE"),
            action: Some(PressAndRelease(Button::Both)),
        }],
    ]
    .concat();

    gen_automation(steps)
}

// Generate automation file for `e2e::ledger_tests::masp_tx_and_queries`
pub fn gen_automation_e2e_masp_tx_and_queries() -> Automation {
    let view_key_steps = || -> Steps {
        [
            please_review_steps(),
            vec![Step::Expect {
                text: Text("Ext Full View Key (1/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Ext Full View Key (2/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Ext Full View Key (3/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Ext Full V...w Key (4/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Ext Full View Key (5/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Ext Full V...w Key (6/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("HD Path"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("APPROVE"),
                action: Some(PressAndRelease(Button::Both)),
            }],
        ]
        .concat()
    };

    let shielded_transfer_steps = || -> Steps {
        [
            please_review_steps(),
            vec![
                Step::Expect {
                    text: Text("Type"),
                    action: None,
                },
                Step::Expect {
                    text: Text("Transfer"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            vec![Step::Expect {
                text: Text("Sender (1/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (2/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (3/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (4/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (5/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (6/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sending Token"),
                action: None,
            }],
            address_steps(),
            vec![
                Step::Expect {
                    text: Text("Sending Amount"),
                    action: None,
                },
                Step::Expect {
                    text: Text("20.0"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            // Receiver of the transferred amount
            vec![Step::Expect {
                text: Text("Destination (1/2)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Destination (2/2)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Receiving Token"),
                action: None,
            }],
            address_steps(),
            vec![
                Step::Expect {
                    text: Text("Receiving Amount"),
                    action: None,
                },
                Step::Expect {
                    text: Text("7.0"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            // The change of balance that is kept by the sender
            vec![Step::Expect {
                text: Text("Destination (1/2)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Destination (2/2)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Receiving Token"),
                action: None,
            }],
            address_steps(),
            vec![
                Step::Expect {
                    text: Text("Receiving Amount"),
                    action: None,
                },
                Step::Expect {
                    text: Text("13.0"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            vec![Step::Expect {
                text: Text("APPROVE"),
                action: Some(PressAndRelease(Button::Both)),
            }],
        ]
        .concat()
    };

    let unshielding_transfer_steps = || -> Steps {
        [
            please_review_steps(),
            vec![
                Step::Expect {
                    text: Text("Type"),
                    action: None,
                },
                Step::Expect {
                    text: Text("Transfer"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            vec![Step::Expect {
                text: Text("Sender (1/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (2/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (3/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (4/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (5/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sender (6/6)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Sending Token"),
                action: None,
            }],
            address_steps(),
            vec![
                Step::Expect {
                    text: Text("Sending Amount"),
                    action: None,
                },
                Step::Expect {
                    text: Text("7.0"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            // Receiver of the unshielded amount
            vec![Step::Expect {
                text: Text("Destination"),
                action: None,
            }],
            address_steps(),
            vec![Step::Expect {
                text: Text("Receiving Token"),
                action: None,
            }],
            address_steps(),
            vec![
                Step::Expect {
                    text: Text("Receiving Amount"),
                    action: None,
                },
                Step::Expect {
                    text: Text("5.0"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            // The change of balance that is kept by the sender
            vec![Step::Expect {
                text: Text("Destination (1/2)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Destination (2/2)"),
                action: Some(PressAndRelease(Button::Right)),
            }],
            vec![Step::Expect {
                text: Text("Receiving Token"),
                action: None,
            }],
            address_steps(),
            vec![
                Step::Expect {
                    text: Text("Receiving Amount"),
                    action: None,
                },
                Step::Expect {
                    text: Text("2.0"),
                    action: Some(PressAndRelease(Button::Right)),
                },
            ],
            vec![Step::Expect {
                text: Text("APPROVE"),
                action: Some(PressAndRelease(Button::Both)),
            }],
        ]
        .concat()
    };

    let steps: Steps = [
        // _____________________________________________________________________
        // 1. tx - shield
        please_review_steps(),
        vec![
            Step::Expect {
                text: Text("Type"),
                action: None,
            },
            Step::Expect {
                text: Text("Transfer"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Sender"),
            action: None,
        }],
        address_steps(),
        vec![Step::Expect {
            text: Text("Sending Token"),
            action: None,
        }],
        address_steps(),
        vec![
            Step::Expect {
                text: Text("Sending Amount"),
                action: None,
            },
            Step::Expect {
                text: Text("20.0"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("Destination (1/2)"),
            action: Some(PressAndRelease(Button::Right)),
        }],
        vec![Step::Expect {
            text: Text("Destination (2/2)"),
            action: Some(PressAndRelease(Button::Right)),
        }],
        vec![Step::Expect {
            text: Text("Receiving Token"),
            action: None,
        }],
        address_steps(),
        vec![
            Step::Expect {
                text: Text("Receiving Amount"),
                action: None,
            },
            Step::Expect {
                text: Text("20.0"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
        vec![Step::Expect {
            text: Text("APPROVE"),
            action: Some(PressAndRelease(Button::Both)),
        }],
        // _____________________________________________________________________
        // 2. tx - shielded transfer
        view_key_steps(),
        // The same steps are repeated twice, first to generate the signature
        // on the device ...
        shielded_transfer_steps(),
        // ... then to obtain the signature out of the device
        shielded_transfer_steps(),
        // _____________________________________________________________________
        // 3. tx - unshielding transfer
        view_key_steps(),
        // The same steps are repeated twice, first to generate the signature
        // on the device ...
        unshielding_transfer_steps(),
        // ... then to obtain the signature out of the device
        unshielding_transfer_steps(),
    ]
    .concat();

    gen_automation(steps)
}

type Steps = Vec<Step>;

#[derive(Debug, Clone)]
enum Step {
    Expect {
        /// Single line of text
        text: TextOrRegex,
        action: Option<StepAction>,
    },
}

#[derive(Debug, Clone)]
enum TextOrRegex {
    Text(&'static str),
    Regex(&'static str),
}
use TextOrRegex::*;

#[derive(Debug, Clone)]
enum StepAction {
    PressAndRelease(Button),
}
use StepAction::*;

#[derive(Debug, Clone, Copy)]
enum Button {
    #[allow(dead_code)]
    Left,
    Right,
    Both,
}

fn please_review_steps() -> Steps {
    vec![
        Step::Expect {
            text: Text("Please"),
            action: None,
        },
        Step::Expect {
            text: Text("review"),
            action: Some(PressAndRelease(Button::Right)),
        },
    ]
}

fn address_steps() -> Steps {
    vec![
        // Address is split on 3 lines:
        Step::Expect {
            text: Regex(r"tnam1\w+"),
            action: None,
        },
        Step::Expect {
            text: Regex(r"\w+"),
            action: None,
        },
        Step::Expect {
            text: Regex(r"\w+"),
            action: Some(PressAndRelease(Button::Right)),
        },
    ]
}

fn fee_steps() -> Steps {
    [
        vec![Step::Expect {
            text: Text("Fee token"),
            action: None,
        }],
        address_steps(),
        vec![
            Step::Expect {
                text: Text("Fee"),
                action: None,
            },
            Step::Expect {
                text: Regex(r"\d+\.\d+"),
                action: Some(PressAndRelease(Button::Right)),
            },
        ],
    ]
    .concat()
}

fn gen_automation(steps: Steps) -> Automation {
    let mut automation = Automation {
        version: 1,
        rules: vec![],
    };

    let mut step_cond_num = 0;

    for step in steps {
        match step {
            Step::Expect { text, action } => {
                let mut rule = start_a_rule(&mut step_cond_num);

                match text {
                    TextOrRegex::Text(text) => {
                        rule.text = Some(text);
                    }
                    TextOrRegex::Regex(regex) => {
                        rule.regex = Some(regex);
                    }
                }

                if let Some(action) = action {
                    match action {
                        StepAction::PressAndRelease(button) => {
                            match button {
                                Button::Left => {
                                    // Generate 2 actions - one to press and one
                                    // to release

                                    // Press
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_LEFT,
                                            true,
                                        ),
                                    ));

                                    // Release
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_LEFT,
                                            false,
                                        ),
                                    ));
                                }
                                Button::Right => {
                                    // Generate 2 action - one to press and one
                                    // to release

                                    // Press
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_RIGHT,
                                            true,
                                        ),
                                    ));

                                    // Release
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_RIGHT,
                                            false,
                                        ),
                                    ));
                                }
                                Button::Both => {
                                    // Generate 4 actions - two to press and two
                                    // to release

                                    // Press left
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_LEFT,
                                            true,
                                        ),
                                    ));

                                    // Press right
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_RIGHT,
                                            true,
                                        ),
                                    ));

                                    // Release left
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_LEFT,
                                            false,
                                        ),
                                    ));

                                    // Release right
                                    rule.actions.push(Action::Button(
                                        ActionButton::new(
                                            BUTTON_NUM_RIGHT,
                                            false,
                                        ),
                                    ));
                                }
                            }
                        }
                    }
                }

                automation.rules.push(rule);
            }
        }
    }

    automation
}

fn start_a_rule(num: &mut i32) -> Rule {
    let step_cond_varname = format!("step-{num}");

    // The step condition must be unset (~= not executed)
    let step_cond = Condition {
        varname: step_cond_varname.clone(),
        value: false,
    };
    // Set the step condition as done
    let step_cond_action =
        Action::SetBool(ActionSetBool::new(step_cond_varname, true));

    let mut rule = Rule {
        conditions: vec![step_cond],
        actions: vec![step_cond_action],
        ..Default::default()
    };

    if *num > 0 {
        // Require that the previous step must be done
        rule.conditions.push(Condition {
            varname: format!("step-{}", *num - 1),
            value: true,
        })
    }

    *num += 1;
    rule
}

#[derive(Debug, Serialize)]
pub struct Automation {
    version: u64,
    rules: Vec<Rule>,
}

#[derive(Debug, Serialize, Default)]
pub struct Rule {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regex: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conditions: Vec<Condition>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actions: Vec<Action>,
}

#[derive(Debug, Serialize_tuple)]
pub struct Condition {
    varname: String,
    value: bool,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Action {
    Button(ActionButton),
    SetBool(ActionSetBool),
}

#[derive(Debug, Serialize_tuple)]
pub struct ActionButton {
    r#type: &'static str,
    num: u8,
    pressed: bool,
}

#[derive(Debug, Serialize_tuple)]
pub struct ActionSetBool {
    r#type: &'static str,
    varname: String,
    value: bool,
}

impl ActionButton {
    fn new(num: u8, pressed: bool) -> Self {
        Self {
            r#type: "button",
            num,
            pressed,
        }
    }
}

impl ActionSetBool {
    fn new(varname: String, value: bool) -> Self {
        Self {
            r#type: "setbool",
            varname,
            value,
        }
    }
}
