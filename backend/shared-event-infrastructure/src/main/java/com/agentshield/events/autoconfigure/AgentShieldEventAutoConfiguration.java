package com.agentshield.events.autoconfigure;

import com.agentshield.events.amqp.EventAmqpConfiguration;
import com.agentshield.events.amqp.SecurityEventListener;
import com.agentshield.events.inbox.InboxEventProcessor;
import com.agentshield.events.outbox.OutboxDispatcher;
import com.agentshield.events.outbox.OutboxEventWriter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;

@AutoConfiguration
@ConditionalOnClass(name="org.springframework.amqp.rabbit.core.RabbitTemplate")
@EnableScheduling
@Import({EventAmqpConfiguration.class, OutboxEventWriter.class, OutboxDispatcher.class, InboxEventProcessor.class, SecurityEventListener.class})
public class AgentShieldEventAutoConfiguration { }
