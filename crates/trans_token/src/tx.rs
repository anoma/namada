//! Token transfers

use std::borrow::Cow;

use namada_core::address::Address;
use namada_events::{EmitEvents, EventLevel};
use namada_tx_env::{Result, TxEnv};

use crate::event::{TokenEvent, TokenOperation};
use crate::{read_balance, Amount, UserAccount};

/// Transfer transparent token, insert the verifier expected by the VP and an
/// emit an event.
pub fn transfer<ENV>(
    env: &mut ENV,
    src: &Address,
    dest: &Address,
    token: &Address,
    amount: Amount,
    event_desc: Cow<'static, str>,
) -> Result<()>
where
    ENV: TxEnv + EmitEvents,
{
    if amount.is_zero() || src == dest {
        return Ok(());
    }

    // The tx must be authorized by the source and destination addresses
    env.insert_verifier(src)?;
    env.insert_verifier(dest)?;
    if token.is_internal() {
        // Established address tokens do not have VPs themselves, their
        // validation is handled by the `Multitoken` internal address, but
        // internal token addresses have to verify the transfer
        env.insert_verifier(token)?;
    }

    crate::storage::transfer(env, token, src, dest, amount)?;

    env.emit(TokenEvent {
        descriptor: event_desc,
        level: EventLevel::Tx,
        operation: TokenOperation::transfer(
            UserAccount::Internal(src.clone()),
            UserAccount::Internal(dest.clone()),
            token.clone(),
            amount.into(),
            read_balance(env, token, src)?.into(),
            Some(read_balance(env, token, dest)?.into()),
        ),
    });

    Ok(())
}

#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use namada_core::address::testing::{
        arb_address, arb_non_internal_address,
    };
    use namada_core::token::testing::arb_amount;
    use namada_core::uint::Uint;
    use namada_core::{address, token};
    use namada_events::extend::EventAttributeEntry;
    use namada_tests::tx::{ctx, tx_host_env};
    use proptest::prelude::*;

    use super::*;
    use crate::event::{PostBalances, SourceAccounts, TargetAccounts};

    const EVENT_DESC: Cow<'static, str> = Cow::Borrowed("event-desc");

    proptest! {
        #[test]
        fn test_valid_transfer_tx(
            (src, dest, token) in (
                arb_non_internal_address(),
                arb_non_internal_address(),
                arb_address()
            ).prop_filter("unique addresses", |(src, dest, token)|
                src != dest && dest != token && src != token),

            amount in arb_amount(),
        ) {
            test_valid_transfer_tx_aux(src, dest, token, amount)
        }
    }

    fn test_valid_transfer_tx_aux(
        src: Address,
        dest: Address,
        token: Address,
        amount: Amount,
    ) {
        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &dest, &token]);
            tx_env.credit_tokens(&src, &token, amount);
        });
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), amount);

        transfer(ctx(), &src, &dest, &token, amount, EVENT_DESC).unwrap();

        // Dest received the amount
        assert_eq!(read_balance(ctx(), &token, &dest).unwrap(), amount);

        // Src spent the amount
        assert_eq!(
            read_balance(ctx(), &token, &src).unwrap(),
            token::Amount::zero()
        );

        tx_host_env::with(|tx_env| {
            // Internal token address have to be part of the verifier set
            assert!(!token.is_internal() || tx_env.verifiers.contains(&token));
            // Src and dest should always verify
            assert!(tx_env.verifiers.contains(&src));
            assert!(tx_env.verifiers.contains(&dest));
        });

        // The transfer must emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert_eq!(events.len(), 1);
            let event = events[0].clone();
            assert_eq!(event.level(), &EventLevel::Tx);
            assert_eq!(event.kind(), &crate::event::types::TRANSFER);
            let attrs = event.into_attributes();
            let amount_uint: Uint = amount.into();

            let exp_balances = if src < dest {
                format!(
                    "[[[\"internal-address/{src}\",\"{token}\"],\"0\"],[[\"\
                     internal-address/{dest}\",\"{token}\"],\"{amount_uint}\"\
                     ]]",
                )
            } else {
                format!(
                    "[[[\"internal-address/{dest}\",\"{token}\"],\"\
                     {amount_uint}\"],[[\"internal-address/{src}\",\"{token}\"\
                     ],\"0\"]]",
                )
            };
            let exp_sources = format!(
                "[[[\"internal-address/{src}\",\"{token}\"],\"{amount_uint}\"\
                 ]]",
            );
            let exp_targets = format!(
                "[[[\"internal-address/{dest}\",\"{token}\"],\"{amount_uint}\"\
                 ]]",
            );

            itertools::assert_equal(
                attrs,
                BTreeMap::from_iter([
                    (PostBalances::KEY.to_string(), exp_balances),
                    (SourceAccounts::KEY.to_string(), exp_sources),
                    (TargetAccounts::KEY.to_string(), exp_targets),
                    (
                        "token-event-descriptor".to_string(),
                        EVENT_DESC.to_string(),
                    ),
                ]),
            );
        })
    }

    #[test]
    fn test_transfer_tx_zero_amount_is_noop() {
        let src = address::testing::established_address_1();
        let dest = address::testing::established_address_2();
        let token = address::testing::established_address_3();
        let amount = token::Amount::zero();
        let src_balance = token::Amount::native_whole(1);
        let dest_balance = token::Amount::native_whole(1);

        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &dest, &token]);
            tx_env.credit_tokens(&src, &token, src_balance);
            tx_env.credit_tokens(&dest, &token, src_balance);
        });

        transfer(ctx(), &src, &dest, &token, amount, EVENT_DESC).unwrap();

        // Dest balance is still the same
        assert_eq!(read_balance(ctx(), &token, &dest).unwrap(), dest_balance);

        // Src balance is still the same
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), src_balance);

        // Verifiers set is empty
        tx_host_env::with(|tx_env| {
            assert!(tx_env.verifiers.is_empty());
        });

        // Must no emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert!(events.is_empty());
        });
    }

    #[test]
    fn test_transfer_tx_src_eq_dest_is_noop() {
        let src = address::testing::established_address_1();
        let dest = address::testing::established_address_1();
        assert_eq!(src, dest);
        let token = address::testing::established_address_2();
        let amount = token::Amount::zero();
        let src_balance = token::Amount::native_whole(1);
        let dest_balance = token::Amount::native_whole(1);

        tx_host_env::init();

        tx_host_env::with(|tx_env| {
            tx_env.spawn_accounts([&src, &dest, &token]);
            tx_env.credit_tokens(&src, &token, src_balance);
            tx_env.credit_tokens(&dest, &token, src_balance);
        });

        transfer(ctx(), &src, &dest, &token, amount, EVENT_DESC).unwrap();

        // Dest balance is still the same
        assert_eq!(read_balance(ctx(), &token, &dest).unwrap(), dest_balance);

        // Src balance is still the same
        assert_eq!(read_balance(ctx(), &token, &src).unwrap(), src_balance);

        // Verifiers set is empty
        tx_host_env::with(|tx_env| {
            assert!(tx_env.verifiers.is_empty());
        });

        // Must no emit an event
        tx_host_env::with(|tx_env| {
            let events: Vec<_> = tx_env
                .state
                .write_log()
                .get_events_of::<TokenEvent>()
                .collect();
            assert!(events.is_empty());
        });
    }
}
