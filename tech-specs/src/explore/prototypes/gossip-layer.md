# Gossip layer/Orderbook prototype

tracking issue <https://github.com/heliaxdev/rd-pm/issues/6>

## Goals

## component

### Intent

An intent is a way of describing the need and/or gives of an account.

### Orderbook

The Orderbook has a mempool of intent and gossip intents to other
orderbook. Each orderbook maintains a intent's filter and informs any orderbook
node of it, if an orderbook relay an intent that is not part of that list that
orderbook is blacklisted.

### Matchmaker

The matchmaker transform a linked intent's list into valid transactions. There
will be multiple matchmaker, each describing a way to match a subset of possible
intent. The matchmaker is rewarded when

### proposed order of development

This is not a mandatory development cycle for the prototyping but just to have a
draft on what could be the priority when developping the orderbook.

### v0: base
  * intent
    * Unencrypted
    * Can express basic asset need
  * mempool
    * Intents are kept alive with no restriction
  * Gossip
    * All orderbook are added to gossip list
    * Intents are gossiped to everyone known

### v1: working prototype
  * mempool
    * Add basic whitelist of asset
    * Intents are kept alive with no restriction
  * Gossip
    * Intents are gossiped to orderbook with at least one asset in whitelist
    * Periodically check whitelist of connected orderbooks

### v2 : Incentive logic for match-maker and orderbooks
  * intent
    * Contains a gossip fee
  * gossip
    * Relayed intents are signed with pk of recipient
      : to determine which orderbook to pay when matched, correct logic TBD

### v3
order TBD later
....
