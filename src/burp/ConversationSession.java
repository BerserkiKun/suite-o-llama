package burp;

import java.util.*;
import java.util.concurrent.*;

public class ConversationSession {
    private final LinkedList<Exchange> history = new LinkedList<>();
    private final long sessionId;
    private long lastActivityTime;
    private volatile boolean terminated = false;
    private ScheduledFuture<?> timeoutFuture;
    
    private static class Exchange {
        final String userPrompt;
        final String llmResponse;
        final long timestamp;
        
        Exchange(String userPrompt, String llmResponse) {
            this.userPrompt = userPrompt;
            this.llmResponse = llmResponse;
            this.timestamp = System.currentTimeMillis();
        }
    }
    
    public ConversationSession() {
        this.sessionId = System.currentTimeMillis();
        this.lastActivityTime = System.currentTimeMillis();
    }
    
    public synchronized void addExchange(String userPrompt, String llmResponse) {
        if (terminated) return;
        
        history.add(new Exchange(userPrompt, llmResponse));
        lastActivityTime = System.currentTimeMillis();
        
        // Limit history to prevent context overflow (keep last 20 exchanges)
        while (history.size() > 30) {
            history.removeFirst();
        }
    }
    
    public synchronized String buildConversationPrompt(String currentPrompt) {
        if (terminated || history.isEmpty()) {
            return currentPrompt;
        }
        
        StringBuilder context = new StringBuilder();
        context.append("Previous conversation:\n");
        
        for (Exchange exchange : history) {
            context.append("User: ").append(exchange.userPrompt).append("\n");
            context.append("Assistant: ").append(exchange.llmResponse).append("\n");
        }
        
        context.append("\nCurrent request: ").append(currentPrompt);
        return context.toString();
    }
    
    public synchronized void updateActivity() {
        if (!terminated) {
            lastActivityTime = System.currentTimeMillis();
        }
    }
    
    public synchronized void terminate() {
        if (!terminated) {
            terminated = true;
            if (timeoutFuture != null) {
                timeoutFuture.cancel(false);
            }
        }
    }
    
    public synchronized boolean isTerminated() {
        return terminated;
    }
    
    public synchronized boolean isExpired() {
        return !terminated && (System.currentTimeMillis() - lastActivityTime > 600000); // 10 minutes
    }
    
    public void scheduleTimeout(ScheduledExecutorService scheduler, Runnable onTimeout) {
        timeoutFuture = scheduler.scheduleAtFixedRate(() -> {
            if (isExpired()) {
                terminate();
                onTimeout.run();
            }
        }, 1, 1, TimeUnit.MINUTES); // Check every minute
    }
    
    public synchronized void clearHistory() {
        history.clear();
    }
}