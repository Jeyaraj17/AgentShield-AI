package com.agentshield.events.amqp;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.DirectExchange;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.CorrelationData;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.rabbit.config.SimpleRabbitListenerContainerFactory;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.amqp.core.Declarables;
import org.springframework.amqp.rabbit.annotation.EnableRabbit;
import org.springframework.amqp.rabbit.annotation.RabbitListenerConfigurer;
import org.springframework.amqp.rabbit.connection.CorrelationData.Confirm;
import com.agentshield.events.outbox.EventTransport;

@Configuration
@EnableRabbit
public class EventAmqpConfiguration {
    @Bean
    public Declarables agentShieldEventTopology(@Value("${agentshield.events.queue:agentshield.service.events}") String queueName,
            @Value("${agentshield.events.dead-letter-queue:agentshield.service.events.dlq}") String deadQueueName) {
        TopicExchange exchange = new TopicExchange("agentshield.events", true, false);
        DirectExchange deadExchange = new DirectExchange("agentshield.events.dlx", true, false);
        Queue queue = new Queue(queueName, true, false, false, java.util.Map.of(
                "x-dead-letter-exchange", "agentshield.events.dlx", "x-dead-letter-routing-key", deadQueueName));
        Queue deadQueue = new Queue(deadQueueName, true);
        return new Declarables(exchange, deadExchange, queue, deadQueue,
                BindingBuilder.bind(queue).to(exchange).with("#"),
                BindingBuilder.bind(deadQueue).to(deadExchange).with(deadQueueName));
    }

    @Bean
    @ConditionalOnMissingBean
    EventTransport rabbitEventTransport(RabbitTemplate template,
            @Value("${agentshield.events.exchange:agentshield.events}") String exchange,
            @Value("${agentshield.events.dead-letter-exchange:agentshield.events.dlx}") String deadExchange,
            @Value("${agentshield.events.dead-letter-queue:agentshield.service.events.dlq}") String deadQueue,
            @Value("${agentshield.events.publish-confirm-timeout-ms:3000}") long timeout) {
        return new EventTransport() {
            @Override public void publish(String routingKey, String json) throws Exception { send(exchange, routingKey, json); }
            @Override public void deadLetter(String routingKey, String json) throws Exception { send(deadExchange, deadQueue, json); }
            private void send(String targetExchange, String routingKey, String json) throws Exception {
                CorrelationData correlation = new CorrelationData(java.util.UUID.randomUUID().toString());
                template.convertAndSend(targetExchange, routingKey, json, message -> message, correlation);
                Confirm confirm = correlation.getFuture().get(timeout, java.util.concurrent.TimeUnit.MILLISECONDS);
                if (!confirm.ack() || correlation.getReturned() != null) throw new IllegalStateException("Broker rejected or could not route event");
            }
        };
    }

    @Bean(name="agentshieldEventListenerContainerFactory")
    SimpleRabbitListenerContainerFactory listenerFactory(ConnectionFactory connectionFactory) {
        SimpleRabbitListenerContainerFactory factory = new SimpleRabbitListenerContainerFactory();
        factory.setConnectionFactory(connectionFactory);
        factory.setDefaultRequeueRejected(false);
        factory.setMissingQueuesFatal(false);
        return factory;
    }
}
