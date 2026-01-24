package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class RepeaterAIResponseTab implements IMessageEditorTab {
    private final ExtensionState state;
    private final IMessageEditorController controller;
    private final OllamaClient ollamaClient;
    private final PromptEngine promptEngine;
    
    private JPanel panel;
    private JTextArea promptArea;
    private JTextArea responseArea;
    private JButton analyzeButton;
    private JButton cancelButton;
    private JCheckBox includeRequestCheckbox;
    private byte[] currentMessage;
    
    public RepeaterAIResponseTab(ExtensionState state, IMessageEditorController controller) {
        this.state = state;
        this.controller = controller;
        this.ollamaClient = new OllamaClient(state);
        this.promptEngine = new PromptEngine(state);
        
        initUI();
    }
    
    private void initUI() {
        panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Top: Prompt editor
        JPanel promptPanel = new JPanel(new BorderLayout(5, 5));
        promptPanel.setBorder(BorderFactory.createTitledBorder("Prompt"));
        
        promptArea = new JTextArea(6, 40);
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        promptArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        promptArea.setText("Analyze this HTTP response:\n\n{{full_response}}\n\n" +
                         "Look for sensitive data exposure, security headers, and potential issues.");
        
        promptPanel.add(new JScrollPane(promptArea), BorderLayout.CENTER);
        
        // Control panel
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        analyzeButton = new JButton("Analyze with Ollama");
        analyzeButton.addActionListener(e -> analyzeResponse());
        
        cancelButton = new JButton("Cancel");
        cancelButton.setEnabled(false);
        cancelButton.addActionListener(e -> ollamaClient.cancel());
        
        includeRequestCheckbox = new JCheckBox("Include Request", true);
        includeRequestCheckbox.setToolTipText("Include the request in context for better analysis");
        
        controlPanel.add(analyzeButton);
        controlPanel.add(cancelButton);
        controlPanel.add(new JLabel("  "));
        controlPanel.add(includeRequestCheckbox);
        
        promptPanel.add(controlPanel, BorderLayout.SOUTH);
        
        panel.add(promptPanel, BorderLayout.NORTH);
        
        // Bottom: Response area
        JPanel aiResponsePanel = new JPanel(new BorderLayout());
        aiResponsePanel.setBorder(BorderFactory.createTitledBorder("AI Analysis"));
        
        responseArea = new JTextArea(15, 40);
        responseArea.setEditable(false);
        responseArea.setLineWrap(true);
        responseArea.setWrapStyleWord(true);
        responseArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        responseArea.setText("Click 'Analyze with Ollama' to start analysis");
        
        aiResponsePanel.add(new JScrollPane(responseArea), BorderLayout.CENTER);
        
        panel.add(aiResponsePanel, BorderLayout.CENTER);
    }
    
    private void analyzeResponse() {
        if (currentMessage == null || currentMessage.length == 0) {
            responseArea.setText("No response to analyze");
            return;
        }
        
        // Check Ollama health
        if (!ollamaClient.checkHealth()) {
            responseArea.setText("ERROR: Ollama disconnected\n\n" +
                               "Ensure Ollama is running at: " + state.getOllamaEndpoint());
            return;
        }
        
        IHttpService service = controller.getHttpService();
        byte[] request = controller.getRequest();
        
        RequestContext context;
        if (includeRequestCheckbox.isSelected() && request != null) {
            context = new RequestContext(request, currentMessage, service);
        } else {
            context = new RequestContext(new byte[0], currentMessage, service);
        }
        
        String prompt = promptEngine.processTemplate(promptArea.getText(), context);
        String model = state.getAnalysisModel();
        
        // Check model availability
        if (!ollamaClient.isModelAvailable(model)) {
            responseArea.setText("ERROR: Model not available: " + model + "\n\n" +
                               "Run: ollama pull " + model);
            return;
        }
        
        SwingUtilities.invokeLater(() -> {
            analyzeButton.setEnabled(false);
            cancelButton.setEnabled(true);
            responseArea.setText("Analyzing with " + model + "...");
        });
        
        ollamaClient.generateAsync(prompt, model, new OllamaClient.ResponseCallback() {
            @Override
            public void onSuccess(String response, long timeMs, int estimatedTokens) {
                SwingUtilities.invokeLater(() -> {
                    String result = String.format("Model: %s | Time: %.2fs | Tokens: ~%d\n%s\n\n%s",
                        model, timeMs / 1000.0, estimatedTokens, "=".repeat(60), response);
                    responseArea.setText(result);
                    responseArea.setCaretPosition(0);
                    analyzeButton.setEnabled(true);
                    cancelButton.setEnabled(false);
                });
            }
            
            @Override
            public void onError(String error) {
                SwingUtilities.invokeLater(() -> {
                    responseArea.setText("ERROR: " + error);
                    analyzeButton.setEnabled(true);
                    cancelButton.setEnabled(false);
                });
            }
        });
    }
    
    @Override
    public String getTabCaption() {
        return "Suite-o-llama AI";
    }
    
    @Override
    public Component getUiComponent() {
        return panel;
    }
    
    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        // Only show for responses
        return !isRequest && content != null && content.length > 0;
    }
    
    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        this.currentMessage = content;
    }
    
    @Override
    public byte[] getMessage() {
        // Non-destructive - return original message
        return currentMessage;
    }
    
    @Override
    public boolean isModified() {
        return false;
    }
    
    @Override
    public byte[] getSelectedData() {
        return null;
    }
}
