package com.agentshield.events.inbox;

import com.agentshield.events.contract.SecurityEvent;

@FunctionalInterface
public interface EventHandler { void handle(SecurityEvent event); }
