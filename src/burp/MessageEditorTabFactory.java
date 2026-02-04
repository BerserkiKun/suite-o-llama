package burp;

import java.util.WeakHashMap;

public class MessageEditorTabFactory implements IMessageEditorTabFactory {
    private final ExtensionState state;
    
    // Track the most recent tab states for each controller type
    private static WeakHashMap<IMessageEditorController, RepeaterAITab> lastRequestTabState = new WeakHashMap<>();
    private static WeakHashMap<IMessageEditorController, RepeaterAIResponseTab> lastResponseTabState = new WeakHashMap<>();
    
    public MessageEditorTabFactory(ExtensionState state) {
        this.state = state;
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        if (editable) {
            // For request tabs
            RepeaterAITab newTab = new RepeaterAITab(state, controller);
            
            // Try to inherit state from previous tab with same controller
            RepeaterAITab previousTab = lastRequestTabState.get(controller);
            if (previousTab != null) {
                transferTabState(previousTab, newTab);
            }
            
            lastRequestTabState.put(controller, newTab);
            return newTab;
        } else {
            // For response tabs  
            RepeaterAIResponseTab newTab = new RepeaterAIResponseTab(state, controller);
            
            // Try to inherit state from previous tab with same controller
            RepeaterAIResponseTab previousTab = lastResponseTabState.get(controller);
            if (previousTab != null) {
                transferTabState(previousTab, newTab);
            }
            
            lastResponseTabState.put(controller, newTab);
            return newTab;
        }
    }
    
    // Helper method to transfer preserved state between tab instances
    private void transferTabState(RepeaterAITab from, RepeaterAITab to) {
        // Transfer prompt text if not default
        String prompt = from.getCurrentPromptText();  // Use public accessor
        if (prompt != null && !prompt.trim().isEmpty() && 
            !prompt.equals("Analyze this HTTP request for vulnerabilities:\n\n{{full_request}}")) {
            to.getPromptArea().setText(prompt);  // Use public accessor
        }
        
        // Transfer LLM response if exists
        String response = from.getCurrentResponseText();  // Use public accessor
        if (response != null && !response.trim().isEmpty() && 
            !response.contains("Click 'Analyze with Ollama'") &&
            !response.contains("Response loaded") &&
            !response.contains("Load a response")) {
            to.getResponseArea().setText(response);  // Use public accessor
        }
    }
    
    // Overloaded version for response tabs
    private void transferTabState(RepeaterAIResponseTab from, RepeaterAIResponseTab to) {
        // Transfer prompt text if not default
        String prompt = from.getCurrentPromptText();  // Use public accessor
        if (prompt != null && !prompt.trim().isEmpty() && 
            !prompt.equals("Analyze this HTTP response:\n\n" +
                    "Response Headers:\n{{res_headers}}\n\n" +
                    "Response Body:\n{{res_body}}\n\n" +
                    "Look for sensitive data exposure, security headers, and potential issues.")) {
            to.getPromptArea().setText(prompt);  // Use public accessor
        }
        
        // Transfer LLM response if exists
        String response = from.getCurrentResponseText();  // Use public accessor
        if (response != null && !response.trim().isEmpty() && 
            !response.contains("Click 'Analyze with Ollama'") &&
            !response.contains("Response loaded") &&
            !response.contains("Load a response")) {
            to.getResponseArea().setText(response);  // Use public accessor
        }
    }
}