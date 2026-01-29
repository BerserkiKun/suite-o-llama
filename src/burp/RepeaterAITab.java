package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class RepeaterAITab implements IMessageEditorTab {
    private final ExtensionState state;
    private final IMessageEditorController controller;
    private final OllamaClient ollamaClient;
    private final PromptEngine promptEngine;
    
    // DECLARED ALL COMPONENTS AS FIELDS
    private JPanel panel;
    private JTextArea promptArea;
    private JTextArea responseArea;
    private JButton analyzeButton;
    private JButton cancelButton;
    private JButton clearButton;
    private JComboBox<String> modelSelector;
    private byte[] currentMessage;

    // PER-MESSAGE STATE
    private volatile boolean isAnalyzing = false;
    private volatile String requestIdentifier = "";
    private volatile long requestStartTime = 0;
    
    public RepeaterAITab(ExtensionState state, IMessageEditorController controller) {
        this.state = state;
        this.controller = controller;
        this.ollamaClient = new OllamaClient(state); // Each tab gets its own client
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
        promptArea.setText("Analyze this HTTP request for vulnerabilities:\n\n{{full_request}}");
        
        promptPanel.add(new JScrollPane(promptArea), BorderLayout.CENTER);
        
        // Control panel - FIXED: Initialize all buttons as fields
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearResponse());

        analyzeButton = new JButton("Analyze with Ollama");
        analyzeButton.addActionListener(e -> analyzeRequest());
        
        cancelButton = new JButton("Cancel");
        cancelButton.setEnabled(false);
        cancelButton.addActionListener(e -> {
            // Immediate UI feedback
            responseArea.append("\n" + "=".repeat(60) + "\nCancelling request...\n" + "=".repeat(60) + "\n");
            responseArea.setCaretPosition(responseArea.getDocument().getLength());

            // Call the enhanced cancellation
            ollamaClient.cancel();
    
            // Show cancellation in progress
            cancelButton.setEnabled(false);
            cancelButton.setText("Cancelling...");

            // Re-enable after 1 seconds
            new Thread(() -> {
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ie) {}
                SwingUtilities.invokeLater(() -> {
                    cancelButton.setEnabled(true);
                    cancelButton.setText("Cancel");
                });
            }).start();
        });
        
        modelSelector = new JComboBox<>(new String[]{"Analysis Model", "Payload Model"});
        
        controlPanel.add(clearButton);
        controlPanel.add(analyzeButton);
        controlPanel.add(cancelButton);
        controlPanel.add(new JLabel("  "));
        controlPanel.add(modelSelector);
        
        // DEBUG BUTTON - REMOVE AFTER TESTING
        //JButton debugButton = new JButton("Debug Test");
        //debugButton.addActionListener(e -> {
        //    responseArea.append("\n=== DEBUG TEST ===\n");
        //    responseArea.setCaretPosition(responseArea.getDocument().getLength());
        //    state.getStdout().println("DEBUG: Button clicked, responseArea should update");
        //});
        //controlPanel.add(debugButton);
        
        promptPanel.add(controlPanel, BorderLayout.SOUTH);
        
        panel.add(promptPanel, BorderLayout.NORTH);
        
        // Bottom: Response area
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("AI Analysis"));
        
        responseArea = new JTextArea(15, 40);
        responseArea.setEditable(false);
        responseArea.setLineWrap(true);
        responseArea.setWrapStyleWord(true);
        responseArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        responseArea.setText("Click 'Analyze with Ollama' to start analysis");
        
        responsePanel.add(new JScrollPane(responseArea), BorderLayout.CENTER);
        
        panel.add(responsePanel, BorderLayout.CENTER);
    }
    
    private void clearResponse() {
        if (responseArea.getText() != null && !responseArea.getText().trim().isEmpty()) {
            int result = JOptionPane.showConfirmDialog(panel,
                "Clear LLM response history?\n\nRequest will be preserved.",
                "Confirm Clear",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);
        
            if (result == JOptionPane.YES_OPTION) {
                responseArea.setText("");
                state.getStdout().println("Cleared LLM response in Repeater AI tab");
            }
        }
    }

    private void analyzeRequest() {
        // Generate unique ID for this analysis session
        final String analysisId = requestIdentifier + "-" + System.currentTimeMillis();
        final byte[] messageToAnalyze = currentMessage; // Capture at time of click
        
        if (messageToAnalyze == null || messageToAnalyze.length == 0) {
            responseArea.append("\n" + "=".repeat(60) + "\nNo request to analyze\n" + "=".repeat(60) + "\n");
            return;
        }
        
        // Check if this is still the current message
        if (!analysisId.startsWith(requestIdentifier)) {
            state.getStdout().println("[RepeaterAITab] Analysis cancelled - message changed");
            return;
        }
    
        // Check Ollama health
        if (!ollamaClient.checkHealth()) {
            responseArea.append("\n" + "=".repeat(60) + "\nERROR: Ollama disconnected\nEnsure Ollama is running at: " + 
                               state.getOllamaEndpoint() + "\n" + "=".repeat(60) + "\n");
            return;
        }
    
        IHttpService service = controller.getHttpService();
        RequestContext context = new RequestContext(messageToAnalyze, service);
    
        String prompt = promptEngine.processTemplate(promptArea.getText(), context);
        String model = modelSelector.getSelectedIndex() == 0 ? 
                      state.getAnalysisModel() : state.getPayloadModel();
    
        // Check model availability
        if (!ollamaClient.isModelAvailable(model)) {
            responseArea.append("\n" + "=".repeat(60) + "\nERROR: Model not available: " + model + 
                               "\nRun: ollama pull " + model + "\n" + "=".repeat(60) + "\n");
            return;
        }
        
        // Set analyzing state
        isAnalyzing = true;
        requestStartTime = System.currentTimeMillis();
        
        // === UI UPDATE ===
        SwingUtilities.invokeLater(() -> {
            try {
                // Only update if this is still the current analysis
                if (isAnalyzing && analysisId.startsWith(requestIdentifier)) {
                    analyzeButton.setEnabled(false);
                    analyzeButton.setText("Analyzing..."); 
                    cancelButton.setEnabled(true);
                    clearButton.setEnabled(false);
                    modelSelector.setEnabled(false);
                    
                    String separator = "=".repeat(60);
                    String currentText = responseArea.getText();
                    String newText = currentText + 
                        "\n" + separator + 
                        "\nAnalyzing with " + model + "..." + 
                        "\n" + separator + "\n";
                    
                    responseArea.setText(newText);
                    responseArea.setCaretPosition(responseArea.getDocument().getLength());
                    responseArea.repaint();
                }
            } catch (Exception e) {
                state.getStderr().println("[RepeaterAITab] UI update error: " + e.getMessage());
            }
        });
    
        // Create callback with analysis ID check
        ollamaClient.generateAsync(prompt, model, new OllamaClient.ResponseCallback() {
            @Override
            public void onSuccess(String response, long timeMs, int estimatedTokens) {
                // Check if this callback is still valid for the current message
                if (!analysisId.startsWith(requestIdentifier)) return;
                
                SwingUtilities.invokeLater(() -> {
                    // Only update if we're still analyzing the same message
                    if (isAnalyzing && analysisId.startsWith(requestIdentifier)) {
                        double executionTimeSeconds = timeMs / 1000.0;
                    
                        String result = String.format(
                            "\n%s\n✓ ANALYSIS COMPLETE\nModel: %s | Time: %.2fs | Tokens: ~%d\n%s\n\n%s\n%s\n",
                            "=".repeat(60), model, executionTimeSeconds, estimatedTokens,
                            "=".repeat(60), response, "=".repeat(60)
                        );
                    
                        responseArea.append(result);
                        responseArea.setCaretPosition(responseArea.getDocument().getLength());
                        
                        // RESTORE UI
                        resetUIState();
                        state.getStdout().println("[RepeaterAITab] Analysis complete for ID: " + analysisId);
                    }
                });
            }
        
            @Override
            public void onError(String error) {
                // Check if this callback is still valid for the current message
                if (!analysisId.startsWith(requestIdentifier)) return;
                
                final long errorTime = System.currentTimeMillis() - requestStartTime;
                double errorTimeSeconds = errorTime / 1000.0;
            
                SwingUtilities.invokeLater(() -> {
                    if (analysisId.startsWith(requestIdentifier)) {
                        String errorMsg = String.format(
                            "\n%s\n✗ ERROR (after %.2fs)\n%s\n\nCheck Ollama at: %s\n%s\n",
                            "=".repeat(60), errorTimeSeconds, error, 
                            state.getOllamaEndpoint(), "=".repeat(60)
                        );
                    
                        responseArea.append(errorMsg);
                        responseArea.setCaretPosition(responseArea.getDocument().getLength());
                        
                        // RESTORE UI
                        resetUIState();
                    }
                });
            }

            @Override
            public void onCancelled(long cancelTimeMs) {
                // Check if this callback is still valid for the current message
                if (!analysisId.startsWith(requestIdentifier)) return;
                
                SwingUtilities.invokeLater(() -> {
                    if (analysisId.startsWith(requestIdentifier)) {
                        String separator = "=".repeat(60);
                        String cancelMsg = String.format(
                            "\n%s\n✗ REQUEST CANCELLED\nCancellation time: %.2fs\n%s\n",
                            separator, cancelTimeMs / 1000.0, separator
                        );
        
                        responseArea.append(cancelMsg);
                        responseArea.setCaretPosition(responseArea.getDocument().getLength());
                        
                        // RESTORE UI
                        resetUIState();
                    }
                });
            }
        });
    }

    private void resetUIState() {
        isAnalyzing = false;
        
        analyzeButton.setEnabled(true);
        analyzeButton.setText("Analyze with Ollama");
        cancelButton.setEnabled(false);
        clearButton.setEnabled(true);
        modelSelector.setEnabled(true);
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
        // Only show for requests
        state.getStdout().println("[RepeaterAITab] isEnabled() called - isRequest: " + isRequest + ", content length: " + (content != null ? content.length : 0));
        return isRequest;
    }
    
    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        // RESET STATE BEFORE LOADING NEW MESSAGE
        resetStateForNewMessage();
        
        this.currentMessage = content;
        state.getStdout().println("[RepeaterAITab] setMessage() called - length: " + (content != null ? content.length : 0));
        
        // Update UI based on new message
        SwingUtilities.invokeLater(() -> {
            if (content != null && content.length > 0 && isRequest) {
                // Enable analyze button
                analyzeButton.setEnabled(true);
                analyzeButton.setText("Analyze with Ollama");
            } else {
                analyzeButton.setEnabled(false);
            }
            
            // Clear any previous analysis
            responseArea.setText("Click 'Analyze with Ollama' to start analysis");
        });
    }
    
    private void resetStateForNewMessage() {
        // Cancel any ongoing analysis for previous message
        if (isAnalyzing) {
            ollamaClient.cancel();
        }
        
        // Reset all state variables
        isAnalyzing = false;
        requestIdentifier = System.currentTimeMillis() + "-" + hashCode();
        requestStartTime = 0;
    }

    @Override
    public byte[] getMessage() {
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