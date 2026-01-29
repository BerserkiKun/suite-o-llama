package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

public class RepeaterAIResponseTab implements IMessageEditorTab {
    private final ExtensionState state;
    private final IMessageEditorController controller;
    private final OllamaClient ollamaClient;
    private final PromptEngine promptEngine;
    
    // ALL COMPONENTS DECLARED AS FIELDS
    private JPanel panel;
    private JTextArea promptArea;
    private JTextArea responseArea;
    private JButton analyzeButton;
    private JButton cancelButton;
    private JButton clearButton;
    private JCheckBox includeRequestCheckbox;
    private byte[] currentMessage;
    
    private volatile boolean isAnalyzing = false;
    private volatile OllamaClient.ResponseCallback currentCallback;
    private volatile String currentModel;
    private volatile boolean isCancelling = false;
    private volatile long requestStartTime = 0; // Track per-request timing
    private volatile String requestIdentifier = ""; // Unique ID for this request

    public RepeaterAIResponseTab(ExtensionState state, IMessageEditorController controller) {
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
        promptArea.setText("Analyze this HTTP response:\n\n" +
                     "Response Headers:\n{{res_headers}}\n\n" +
                     "Response Body:\n{{res_body}}\n\n" +
                     "Look for sensitive data exposure, security headers, and potential issues.");

        
        promptPanel.add(new JScrollPane(promptArea), BorderLayout.CENTER);
        
        // Control panel - ALL BUTTONS INITIALIZED AS FIELDS
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> clearResponse());

        analyzeButton = new JButton("Analyze with Ollama");
        analyzeButton.addActionListener(e -> analyzeResponse());
        
        cancelButton = new JButton("Cancel");
        cancelButton.setEnabled(false);
        cancelButton.addActionListener(e -> {
            // Immediate UI feedback
            responseArea.append("\n" + "=".repeat(60) + "\nCancelling request...\n" + "=".repeat(60) + "\n");
            responseArea.setCaretPosition(responseArea.getDocument().getLength());
            
            isCancelling = true;
            // Call the enhanced cancellation
            ollamaClient.cancel();
    
            // Show cancellation in progress
            cancelButton.setEnabled(false);
            cancelButton.setText("Cancelling...");

            // Re-enable after 0.5 seconds
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
        
        includeRequestCheckbox = new JCheckBox("Include Request", true);
        includeRequestCheckbox.setToolTipText("Include the request in context for better analysis");
        
        controlPanel.add(clearButton);
        controlPanel.add(analyzeButton);
        controlPanel.add(cancelButton);
        controlPanel.add(new JLabel("  "));
        controlPanel.add(includeRequestCheckbox);
        
        // DEBUG BUTTON - REMOVE AFTER TESTING
        //JButton debugButton = new JButton("Debug Test");
        //debugButton.addActionListener(e -> {
        //    responseArea.append("\n=== DEBUG TEST RESPONSE TAB ===\n");
        //    responseArea.setCaretPosition(responseArea.getDocument().getLength());
        //    state.getStdout().println("[RepeaterAIResponseTab] Debug button clicked");
        //});
        //controlPanel.add(debugButton);
        
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
    
    private void clearResponse() {
        if (responseArea.getText() != null && !responseArea.getText().trim().isEmpty()) {
            int result = JOptionPane.showConfirmDialog(panel,
                "Clear LLM response history?\n\nResponse will be preserved.",
                "Confirm Clear",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);
        
            if (result == JOptionPane.YES_OPTION) {
                responseArea.setText("");
                state.getStdout().println("Cleared LLM response in Response AI tab");
            }
        }
    }

    private void resetStateForNewMessage() {
        // Cancel any ongoing analysis for previous message
        if (isAnalyzing && currentCallback != null) {
            ollamaClient.cancel();
        }
        
        // Reset all state variables
        isAnalyzing = false;
        currentCallback = null;
        isCancelling = false;
        requestStartTime = 0;
        currentMessage = null;
        
        // Generate a unique identifier for this request
        requestIdentifier = System.currentTimeMillis() + "-" + hashCode();
    }

    private void analyzeResponse() {
        // Generate a unique ID for this specific analysis session
        final String analysisId = requestIdentifier + "-" + System.currentTimeMillis();
        final byte[] messageToAnalyze = currentMessage; // Capture at time of click

        if (messageToAnalyze == null || messageToAnalyze.length == 0) {
            state.getStdout().println("[RepeaterAIResponseTab] No currentMessage for ID: " + analysisId);
            responseArea.append("\n" + "=".repeat(60) + "\nNo response to analyze\n" + "=".repeat(60) + "\n");
            return;
        }
        
        // Check if this is still the current message (user hasn't switched)
        if (!analysisId.startsWith(requestIdentifier)) {
            state.getStdout().println("[RepeaterAIResponseTab] Analysis cancelled - message changed");
            return;
        }

        // Check Ollama health
        state.getStdout().println("[RepeaterAIResponseTab] Checking Ollama health...");
        if (!ollamaClient.checkHealth()) {
            state.getStdout().println("[RepeaterAIResponseTab] Ollama health check FAILED");
            responseArea.append("\n" + "=".repeat(60) + "\nERROR: Ollama disconnected\nEnsure Ollama is running at: " + 
                            state.getOllamaEndpoint() + "\n" + "=".repeat(60) + "\n");
            return;
        }

        IHttpService service = controller.getHttpService();
        byte[] request = controller.getRequest();
        
        RequestContext context;
        if (includeRequestCheckbox.isSelected() && request != null) {
            context = new RequestContext(request, messageToAnalyze, service);
        } else {
            context = new RequestContext(new byte[0], messageToAnalyze, service);
        }

        String prompt = promptEngine.processTemplate(promptArea.getText(), context);
        String model = state.getAnalysisModel();
        
        state.getStdout().println("[RepeaterAIResponseTab] Model: " + model);

        // Check model availability
        state.getStdout().println("[RepeaterAIResponseTab] Checking model availability...");
        if (!ollamaClient.isModelAvailable(model)) {
            state.getStdout().println("[RepeaterAIResponseTab] Model NOT available");
            responseArea.append("\n" + "=".repeat(60) + "\nERROR: Model not available: " + model + 
                            "\nRun: ollama pull " + model + "\n" + "=".repeat(60) + "\n");
            return;
        }
        
        // Check model availability
        if (!ollamaClient.isModelAvailable(model)) {
            responseArea.append("\n" + "=".repeat(60) + "\nERROR: Model not available: " + model + 
                           "\nRun: ollama pull " + model + "\n" + "=".repeat(60) + "\n");
            return;
        }
        // Set analyzing state
        isAnalyzing = true;
        currentModel = model;
        requestStartTime = System.currentTimeMillis();
        
        // === CRITICAL FIX: SINGLE ATOMIC UI UPDATE ===
        SwingUtilities.invokeLater(() -> {
            try {
                // Only update if this is still the current analysis
                if (isAnalyzing && analysisId.startsWith(requestIdentifier)) {
                    analyzeButton.setEnabled(false);
                    analyzeButton.setText("Analyzing..."); 
                    cancelButton.setEnabled(true);
                    clearButton.setEnabled(false);
                    includeRequestCheckbox.setEnabled(false);
                    
                    String separator = "=".repeat(60);
                    String currentText = responseArea.getText();
                    String newText = currentText + 
                        "\n" + separator + 
                        "\nAnalyzing response with " + model + "..." + 
                        "\n" + separator + "\n";
                    
                    responseArea.setText(newText);
                    responseArea.setCaretPosition(responseArea.getDocument().getLength());
                    responseArea.repaint();
                }
            } catch (Exception e) {
                state.getStderr().println("[RepeaterAIResponseTab] UI update error: " + e.getMessage());
            }
        });

        // START TIME measurement
        final long startTime = System.currentTimeMillis();
        state.getStdout().println("[RepeaterAIResponseTab] Calling ollamaClient.generateAsync()");

        // Create the callback
        currentCallback = new OllamaClient.ResponseCallback() {
            @Override
            public void onSuccess(String response, long timeMs, int estimatedTokens) {
                // Check if this callback is still valid for the current message
                if (!analysisId.startsWith(requestIdentifier) || isCancelling) return;
                
                state.getStdout().println("[RepeaterAIResponseTab] onSuccess() received");
                SwingUtilities.invokeLater(() -> {
                    // Only update if we're still analyzing the same message
                    if (isAnalyzing && analysisId.startsWith(requestIdentifier) && !isCancelling) {
                        double executionTimeSeconds = timeMs / 1000.0;
                        String separator = "=".repeat(60);
                    
                        String result = String.format(
                            "\n%s\n" +
                            "✓ RESPONSE ANALYSIS COMPLETED\n" +
                            "Model: %s | Time: %.2fs | Tokens: ~%d\n" +
                            "%s\n\n" +
                            "%s\n" +
                            "%s\n",
                            separator,
                            model, executionTimeSeconds, estimatedTokens,
                            separator,
                            response,
                            separator
                        );
                    
                        responseArea.append(result);
                        responseArea.setCaretPosition(responseArea.getDocument().getLength());
                        
                        // RESTORE UI STATE
                        resetUIState();
                        state.getStdout().println("[RepeaterAIResponseTab] Analysis complete for ID: " + analysisId);
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
                    if (analysisId.startsWith(requestIdentifier) && !isCancelling) {
                        String separator = "=".repeat(60);
                    
                        String errorMsg = String.format(
                            "\n%s\n" +
                            "✗ ERROR (after %.2fs)\n" +
                            "%s\n\n" +
                            "Check Ollama at: %s\n" +
                            "%s\n",
                            separator,
                            errorTimeSeconds,
                            error, state.getOllamaEndpoint(),
                            separator
                        );
                    
                        responseArea.append(errorMsg);
                        responseArea.setCaretPosition(responseArea.getDocument().getLength());
                        
                        // RESTORE UI STATE
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
                            "\n%s\n" +
                            "✗ REQUEST CANCELLED\n" +
                            "Cancellation time: %.2fs\n" +
                            "%s\n",
                            separator,
                            cancelTimeMs / 1000.0,
                            separator
                        );
        
                        responseArea.append(cancelMsg);
                        responseArea.setCaretPosition(responseArea.getDocument().getLength());
                        
                        // RESTORE UI STATE
                        resetUIState();
                        isCancelling = false;
                    }
                });
            }
        };
        
        // Store the model and start the analysis
        currentModel = model;
        ollamaClient.generateAsync(prompt, model, currentCallback);
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
        // Only enable for non-empty responses
        boolean shouldEnable = !isRequest && content != null && content.length > 0;
        return shouldEnable;
    }
    
    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        // RESET ALL STATE BEFORE LOADING NEW MESSAGE
        resetStateForNewMessage();
        this.currentMessage = content;
        
        SwingUtilities.invokeLater(() -> {
            // COMPLETELY RESET UI FOR NEW MESSAGE
            responseArea.setText("");  // Clear everything
            
            if (content != null && content.length > 0 && !isRequest) {
                responseArea.setText("Response loaded (" + content.length + " bytes)\n" +
                                "Click 'Analyze with Ollama' to start analysis");
            } else {
                responseArea.setText("No response to analyze");
            }
            
            // Reset buttons to default state
            analyzeButton.setEnabled(content != null && content.length > 0);
            analyzeButton.setText("Analyze with Ollama");
            cancelButton.setEnabled(false);
            cancelButton.setText("Cancel");
            
            responseArea.setCaretPosition(0);
        });
    }

    // new method to reset UI state:
    private void resetUIState() {
    isAnalyzing = false;
    currentCallback = null;
    
    analyzeButton.setEnabled(true);
    analyzeButton.setText("Analyze with Ollama");
    cancelButton.setEnabled(false);
    cancelButton.setText("Cancel");
    clearButton.setEnabled(true);
    includeRequestCheckbox.setEnabled(true);
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