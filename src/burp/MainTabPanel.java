package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.*;
import java.text.SimpleDateFormat;
import java.util.Date;
import javax.swing.JScrollPane; 

public class MainTabPanel extends JPanel implements IMessageEditorController {

    private final ExtensionState state;
    private final OllamaClient ollamaClient;
    private final PromptEngine promptEngine;
    private final AutocompleteEngine autocompleteEngine;

    // UI Components
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private JTextArea promptArea;
    private JTextArea llmResponseArea;

    private JButton sendToServerBtn;
    private JButton sendToLlmBtn;
    private JButton githubBtn;
    private JButton supportDevBtn;
    private JButton clearBtn;
    private JButton cancelBtn;

    private IHttpService currentService;
    private byte[] currentRequest;
    private byte[] currentResponse;
    private AutocompleteContext currentContext;

    private boolean initialEmptyTab = false; // NEW: Track if this is initial empty tab

    public MainTabPanel(ExtensionState state, PromptEngine promptEngine) {
        this.state = state;
        this.ollamaClient = new OllamaClient(state);  // Create per-tab instance
        this.promptEngine = promptEngine;
        this.autocompleteEngine = new AutocompleteEngine(state, this.ollamaClient, promptEngine);
    
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(5, 5, 5, 5));
    
        initUi();
    }

    // NEW: Getter/Setter for initial empty tab status
    public void setInitialEmptyTab(boolean isInitial) {
        this.initialEmptyTab = isInitial;
    }
    
    public boolean isInitialEmptyTab() {
        return initialEmptyTab && !hasContent();
    }

    private void initUi() {
        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setResizeWeight(0.5);  // FIX: Equal split
        verticalSplit.setDividerLocation(0.5);  // FIX: Start at middle

        // ===== Request / Response =====
        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        reqRespSplit.setResizeWeight(0.5); // FIX: Equal horizontal split  
        reqRespSplit.setDividerLocation(0.5); // FIX: Start at middle

        requestEditor = state.getCallbacks()
                .createMessageEditor(this, true);

        responseEditor = state.getCallbacks()
                .createMessageEditor(this, false);

        reqRespSplit.setLeftComponent(wrapPanel("Request", requestEditor.getComponent()));
        reqRespSplit.setRightComponent(wrapPanel("Response", responseEditor.getComponent()));

        // ===== Bottom Panel =====
        JPanel bottomPanel = new JPanel(new BorderLayout(5, 5));

        promptArea = new JTextArea(4, 80);
        promptArea.setBorder(new TitledBorder("Prompt"));
        promptArea.setLineWrap(true);
        promptArea.setWrapStyleWord(true);
        promptArea.setText("Analyze this HTTP request for vulnerabilities:\n\n{{full_request}}");

        llmResponseArea = new JTextArea(6, 80);
        llmResponseArea.setEditable(false);
        llmResponseArea.setBorder(new TitledBorder("LLM Response"));

        bottomPanel.add(new JScrollPane(promptArea), BorderLayout.NORTH);
        bottomPanel.add(new JScrollPane(llmResponseArea), BorderLayout.CENTER);
        bottomPanel.add(buildButtonPanel(), BorderLayout.SOUTH);

        verticalSplit.setTopComponent(reqRespSplit);
        verticalSplit.setBottomComponent(bottomPanel);

        add(verticalSplit, BorderLayout.CENTER);

        hookAutocomplete(promptArea);
        // FIX: Force initial layout
        SwingUtilities.invokeLater(() -> {
            verticalSplit.setDividerLocation(0.5);
            reqRespSplit.setDividerLocation(0.5);
        });
    }

    private JPanel buildButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sendToServerBtn = new JButton("Send to Server");
        sendToLlmBtn = new JButton("Send to LLM");
        cancelBtn = new JButton("Cancel"); // NEW
        githubBtn = new JButton("GitHub");
        clearBtn = new JButton("Clear");
        supportDevBtn = new JButton("Support Development");

        sendToServerBtn.addActionListener(e -> sendToServer());
        sendToLlmBtn.addActionListener(e -> sendToLlm());
        cancelBtn.addActionListener(e -> cancelLlmRequest()); // NEW
        githubBtn.addActionListener(e -> openGitHub());
        clearBtn.addActionListener(e -> clearLLMResponse()); // CHANGED: clearAll() -> clearLLMResponse()
        supportDevBtn.addActionListener(e -> openSupportPage());

        // Initially disable cancel button
        cancelBtn.setEnabled(false);

        // Set saffron color for Support Development button
        supportDevBtn.setBackground(new Color(255, 153, 51));
        supportDevBtn.setOpaque(true);
        supportDevBtn.setBorderPainted(false);

        panel.add(clearBtn);
        panel.add(sendToServerBtn);
        panel.add(sendToLlmBtn);
        panel.add(cancelBtn); // NEW
        panel.add(githubBtn);
        panel.add(supportDevBtn);

        return panel;
    }

    private JPanel wrapPanel(String title, Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    // ================= NEW: hasContent() method for tab closing =================
    public boolean hasContent() {
        // Check if tab has any meaningful content
        if (currentRequest != null && currentRequest.length > 0) return true;
        if (currentResponse != null && currentResponse.length > 0) return true;
        
        // Check prompt area for non-default content
        String prompt = promptArea.getText();
        if (prompt != null && !prompt.trim().isEmpty()) {
            // Check if it's NOT the default prompt
            if (!prompt.trim().equals("Analyze this HTTP request for vulnerabilities:\n\n{{full_request}}")) {
                return true;
            }
        }
        
        if (llmResponseArea.getText() != null && !llmResponseArea.getText().trim().isEmpty()) return true;
        return false;
    }

    private void hookAutocomplete(JTextArea area) {
        area.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (e.isControlDown() && e.getKeyCode() == KeyEvent.VK_SPACE) {
                    showAutocomplete(area);
                }
            }
        });
    }

    private void showAutocomplete(JTextArea textArea) {
        if (currentContext == null || !currentContext.hasService()) {
            return;
        }

        int caretPos = textArea.getCaretPosition();
        String text = textArea.getText();

        String paramContext = extractParameterContext(text, caretPos);
        if (paramContext == null) {
            return;
        }

        if (currentContext != null && currentContext.getMessage() != null) {
            IHttpRequestResponse message = currentContext.getMessage();
            RequestContext requestContext = new RequestContext(
                message.getRequest(),
                message.getResponse(),
                message.getHttpService()
            );
    
            autocompleteEngine.generatePayloads(
                requestContext,
                paramContext,
                new AutocompleteEngine.PayloadCallback() {
                    @Override
                    public void onPayloadsGenerated(String[] payloads) {
                        if (payloads.length > 0) {
                            SwingUtilities.invokeLater(() ->
                                insertSuggestion(textArea, caretPos, payloads[0])
                            );
                        }
                    }
                }
            );
        }
    }

    private String extractParameterContext(String text, int caretPos) {
        if (caretPos <= 0 || caretPos > text.length()) {
            return null;
        }

        int start = caretPos - 1;
        while (start > 0 && !Character.isWhitespace(text.charAt(start))) {
            start--;
        }

        return text.substring(start, caretPos).trim();
    }

    private void cancelLlmRequest() {
        // Immediate UI feedback
        llmResponseArea.append("\n" + "=".repeat(60) + "\nCancelling LLM request...\n" + "=".repeat(60) + "\n");
        llmResponseArea.setCaretPosition(llmResponseArea.getDocument().getLength());
    
        // Call cancellation
        ollamaClient.cancel();
    
        // Update UI
        cancelBtn.setEnabled(false);
        cancelBtn.setText("Cancelling...");
        sendToLlmBtn.setEnabled(true);
        sendToLlmBtn.setText("Send to LLM");
    
        // Re-enable cancel button after delay
        new Thread(() -> {
            try { Thread.sleep(2000); } catch (InterruptedException ie) {}
            SwingUtilities.invokeLater(() -> {
                cancelBtn.setEnabled(true);
                cancelBtn.setText("Cancel");
            });
        }).start();
    }

    private void insertSuggestion(JTextArea area, int caretPos, String suggestion) {
        try {
            area.getDocument().insertString(caretPos, suggestion, null);
        } catch (Exception ignored) {
        }
    }

    private void openSupportPage() {
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop().browse(
                    new java.net.URI("https://github.com/BerserkiKun/suite-o-llama?tab=readme-ov-file#support-development")
                );
                state.getStdout().println("Opened Support Development page in browser");
            }
        } catch (Exception e) {
            state.getStderr().println("Error opening support page: " + e.getMessage());
        }
    }

    private void openGitHub() {
        try {
            if (java.awt.Desktop.isDesktopSupported()) {
                java.awt.Desktop.getDesktop().browse(
                    new java.net.URI("https://github.com/berserkikun")
                );
                state.getStdout().println("Opened GitHub profile in browser");
            }
        } catch (Exception e) {
            state.getStderr().println("Error opening GitHub: " + e.getMessage());
        }
    }

    private void sendToServer() {
        byte[] editedRequest = requestEditor.getMessage(); // FIX: Use editor content
        if (currentService == null || currentRequest == null) {
            JOptionPane.showMessageDialog(this, "No request to send", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        currentRequest = editedRequest; // FIX: Update stored reference
        sendToServerBtn.setEnabled(false);
        sendToServerBtn.setText("Sending...");
    
        new Thread(() -> {
            try {
                IHttpRequestResponse resp = state.getCallbacks().makeHttpRequest(currentService, editedRequest);
            
                SwingUtilities.invokeLater(() -> {
                    currentResponse = resp.getResponse();
                    responseEditor.setMessage(currentResponse, false);
                    sendToServerBtn.setEnabled(true);
                    sendToServerBtn.setText("Send to Server");
                
                    if (resp != null) {
                        currentContext = AutocompleteContext.from(resp);
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(MainTabPanel.this, "Request failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                    sendToServerBtn.setEnabled(true);
                    sendToServerBtn.setText("Send to Server");
                });
            }
        }).start();
    }

        private void sendToLlm() {
            byte[] editedRequest = requestEditor.getMessage(); // FIX: Use editor content
            String prompt = promptArea.getText();
            if (prompt.isEmpty() || currentRequest == null) {
                JOptionPane.showMessageDialog(this, "Please load a request and enter a prompt", "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            currentRequest = editedRequest; // FIX: Update stored reference
            // Reset any previous cancellation state
            ollamaClient.cancel(); // Ensure previous request is cancelled
            try {
                Thread.sleep(100); // Small delay to ensure clean state
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            RequestContext context = new RequestContext(editedRequest, currentService); // FIX: Use edited request
            String finalPrompt = promptEngine.createAnalysisPrompt(context, prompt);
            String model = state.getAnalysisModel();
            
            // ========== FIX: BATCH ALL INITIAL UI UPDATES TOGETHER ==========
            SwingUtilities.invokeLater(() -> {
                // Clear any partial responses first
                String currentText = llmResponseArea.getText();
                if (!currentText.endsWith("\n")) {
                    currentText += "\n";
                }
                
                String separator = "=".repeat(60);
                String analyzingText = currentText + separator + "\nAnalyzing with " + model + "...\n" + separator + "\n";
                
                llmResponseArea.setText(analyzingText);
                llmResponseArea.setCaretPosition(llmResponseArea.getDocument().getLength());
                
                // Reset UI state
                sendToLlmBtn.setEnabled(false);
                sendToLlmBtn.setText("Analyzing...");
                cancelBtn.setEnabled(true);
                cancelBtn.setText("Cancel");
                
                // Force UI update
                llmResponseArea.repaint();
            });
            
            // ========== FIX: Use a fresh callback each time ==========
            OllamaClient.ResponseCallback callback = new OllamaClient.ResponseCallback() {
                private final long startTime = System.currentTimeMillis();
                
                @Override
                public void onSuccess(String response, long timeMs, int estimatedTokens) {
                    if (Thread.currentThread().isInterrupted()) {
                        return; // Don't update UI if cancelled
                    }
                    
                    SwingUtilities.invokeLater(() -> {
                        // Verify this callback is still valid (not replaced)
                        double executionTimeSeconds = timeMs / 1000.0;
                        String separator = "=".repeat(60);
                        String result = String.format(
                            "\n%s\n" +
                            "✓ ANALYSIS COMPLETE\n" +
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
                        
                        // Only append if this is still the current operation
                        if (sendToLlmBtn.getText().equals("Analyzing...")) {
                            llmResponseArea.append(result);
                            llmResponseArea.setCaretPosition(llmResponseArea.getDocument().getLength());
                            sendToLlmBtn.setEnabled(true);
                            sendToLlmBtn.setText("Send to LLM");
                            cancelBtn.setEnabled(false);
                            cancelBtn.setText("Cancel");
                        }
                    });
                }
                
                @Override
                public void onError(String error) {
                    if (Thread.currentThread().isInterrupted()) {
                        return; // Don't update UI if cancelled
                    }
                    
                    SwingUtilities.invokeLater(() -> {
                        // Only show error if this is still the current operation
                        if (sendToLlmBtn.getText().equals("Analyzing...")) {
                            String separator = "=".repeat(60);
                            String errorMsg = String.format(
                                "\n%s\n" +
                                "✗ ERROR\n" +
                                "%s\n\n" +
                                "Please check:\n" +
                                "1. Ollama is running: ollama serve\n" +
                                "2. Model is available: ollama pull %s\n" +
                                "3. Ollama endpoint: %s\n" +
                                "%s\n",
                                separator,
                                error, model, state.getOllamaEndpoint(),
                                separator
                            );
                        
                            llmResponseArea.append(errorMsg);
                            llmResponseArea.setCaretPosition(llmResponseArea.getDocument().getLength());
                            sendToLlmBtn.setEnabled(true);
                            sendToLlmBtn.setText("Send to LLM");
                            
                            // Disable cancel button after error
                            cancelBtn.setEnabled(false);
                            cancelBtn.setText("Cancel");
                        }
                    });
                }

                // Adding cancellation callback v2.2.0
                @Override
                public void onCancelled(long cancelTimeMs) {
                    SwingUtilities.invokeLater(() -> {
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
                            
                        // Always show cancellation message
                        llmResponseArea.append(cancelMsg);
                        llmResponseArea.setCaretPosition(llmResponseArea.getDocument().getLength());
                        sendToLlmBtn.setEnabled(true);
                        sendToLlmBtn.setText("Send to LLM");
                        cancelBtn.setEnabled(false);
                        cancelBtn.setText("Cancel");
                    });
                }
            };
            
            // Start the generation
            ollamaClient.generateAsync(finalPrompt, model, callback);
        }

    // ================= CHANGED: clearLLMResponse() instead of clearAll() =================
    private void clearLLMResponse() {
        // Only clear LLM response, nothing else
        if (llmResponseArea.getText() != null && !llmResponseArea.getText().trim().isEmpty()) {
            int result = JOptionPane.showConfirmDialog(this,
                "Clear LLM response history?\n\nRequest, response, and prompt will be preserved.",
                "Confirm Clear",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);
        
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }
    
        // Clear only LLM response
        llmResponseArea.setText("");
        state.getStdout().println("Cleared LLM response history");
    }

    // ================= IMessageEditorController =================
    @Override
    public IHttpService getHttpService() {
        return currentService;
    }

    @Override
    public byte[] getRequest() {
        return currentRequest;
    }

    @Override
    public byte[] getResponse() {
        return currentResponse;
    }

    public String getDefaultTabName() {
        if (currentService != null && currentRequest != null) {
            try {
                IRequestInfo reqInfo = state.getHelpers().analyzeRequest(currentService, currentRequest);
                String method = reqInfo.getMethod();
                String path = reqInfo.getUrl().getPath();
                return method + " " + path;
            } catch (Exception e) {
                return "Request";
            }
        }
        return "New Tab";
    }
    
    // ================= Public Methods for Tab Integration =================
    public void loadRequest(IHttpRequestResponse message) {
        currentService = message.getHttpService();
        currentRequest = message.getRequest();
        currentResponse = message.getResponse();

        requestEditor.setMessage(currentRequest, true);
        responseEditor.setMessage(currentResponse, false);

        currentContext = AutocompleteContext.from(message);
    }
    public void cleanup() {
    if (ollamaClient != null) {
        ollamaClient.shutdown();
    }
}
    public void loadRequestOnly(byte[] request, IHttpService service) {
        currentService = service;
        currentRequest = request;
        currentResponse = null;
        currentContext = null;
    
        requestEditor.setMessage(currentRequest, true);
        responseEditor.setMessage(null, false);
        llmResponseArea.setText("");
    
        // Set default prompt if prompt area is empty
        if (promptArea != null && (promptArea.getText() == null || promptArea.getText().trim().isEmpty())) {
            promptArea.setText("Analyze this HTTP request for vulnerabilities:\n\n{{full_request}}");
        }
    
        // Note: We can't create AutocompleteContext without IHttpRequestResponse
        // So currentContext remains null
    }
}