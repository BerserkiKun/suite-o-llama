package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.awt.event.*;

public class MainTab extends JPanel implements ITab, IMessageEditorController {

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
    private JButton renderBtn;

    private IHttpService currentService;
    private byte[] currentRequest;
    private byte[] currentResponse;
    private AutocompleteContext currentContext;

    public MainTab(ExtensionState state, OllamaClient ollamaClient, PromptEngine promptEngine, AutocompleteEngine autocompleteEngine)
    {
        this.state = state;
        this.ollamaClient = ollamaClient;
        this.promptEngine = promptEngine;
        this.autocompleteEngine = autocompleteEngine;
    
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(5, 5, 5, 5));
    
        initUi();
    }

    private void initUi() {
        JSplitPane verticalSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        verticalSplit.setResizeWeight(0.6);

        // ===== Request / Response =====
        JSplitPane reqRespSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        reqRespSplit.setResizeWeight(0.5);

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
    }

    private JPanel buildButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        sendToServerBtn = new JButton("Send to Server");
        sendToLlmBtn = new JButton("Send to LLM");
        renderBtn = new JButton("Render");
        JButton clearBtn = new JButton("Clear");  // New button

        sendToServerBtn.addActionListener(e -> sendToServer());
        sendToLlmBtn.addActionListener(e -> sendToLlm());
        renderBtn.addActionListener(e -> renderResponse());
        clearBtn.addActionListener(e -> clearAll());  // New action
        panel.add(clearBtn);  // Add to panel

        panel.add(sendToServerBtn);
        panel.add(sendToLlmBtn);
        panel.add(renderBtn);

        return panel;
    }

    private JPanel wrapPanel(String title, Component c) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new TitledBorder(title));
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    // ================= PART 2 METHODS =================

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

    private void insertSuggestion(JTextArea area, int caretPos, String suggestion) {
        try {
            area.getDocument().insertString(caretPos, suggestion, null);
        } catch (Exception ignored) {
        }
    }

    private void sendToServer() {
    if (currentService == null || currentRequest == null) {
        JOptionPane.showMessageDialog(this, "No request to send", "Error", JOptionPane.ERROR_MESSAGE);
        return;
    }
    
    sendToServerBtn.setEnabled(false);
    sendToServerBtn.setText("Sending...");
    
    new Thread(() -> {
        try {
            IHttpRequestResponse resp = state.getCallbacks().makeHttpRequest(currentService, currentRequest);
            
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
                JOptionPane.showMessageDialog(MainTab.this, "Request failed: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
                sendToServerBtn.setEnabled(true);
                sendToServerBtn.setText("Send to Server");
            });
        }
    }).start();
}

    private void sendToLlm() {
    String prompt = promptArea.getText();
    if (prompt.isEmpty() || currentRequest == null) {
        JOptionPane.showMessageDialog(this, "Please load a request and enter a prompt", "Error", JOptionPane.ERROR_MESSAGE);
        return;
    }

    RequestContext context = new RequestContext(currentRequest, currentService);
    String finalPrompt = promptEngine.createAnalysisPrompt(context, prompt);
    String model = state.getAnalysisModel();
    
    // Show "Analyzing..." status
    llmResponseArea.setText("Analyzing with " + model + "...\n" + "=".repeat(60) + "\n\n");
    
    // Disable button during processing
    sendToLlmBtn.setEnabled(false);
    sendToLlmBtn.setText("Analyzing...");
    
    ollamaClient.generateAsync(finalPrompt, model, new OllamaClient.ResponseCallback() {
        @Override
        public void onSuccess(String response, long timeMs, int estimatedTokens) {
            SwingUtilities.invokeLater(() -> {
                String result = String.format("Model: %s | Time: %.2fs | Tokens: ~%d\n%s\n\n%s",
                    model, timeMs / 1000.0, estimatedTokens, "=".repeat(60), response);
                llmResponseArea.setText(result);
                sendToLlmBtn.setEnabled(true);
                sendToLlmBtn.setText("Send to LLM");
            });
        }
        
        @Override
        public void onError(String error) {
            SwingUtilities.invokeLater(() -> {
                llmResponseArea.setText("ERROR: " + error + "\n\nPlease check:\n1. Ollama is running: ollama serve\n2. Model is pulled: ollama pull " + model);
                sendToLlmBtn.setEnabled(true);
                sendToLlmBtn.setText("Send to LLM");
                JOptionPane.showMessageDialog(MainTab.this, "AI Error: " + error, "Error", JOptionPane.ERROR_MESSAGE);
            });
        }
    });
}

    private void clearAll() {
        // Ask for confirmation if there's content
        boolean hasContent = false;
    
        // Check request editor
        if (requestEditor.getMessage() != null && requestEditor.getMessage().length > 0) {
            hasContent = true;
        }
    
        //  Check response editor  
        if (responseEditor.getMessage() != null && responseEditor.getMessage().length > 0) {
        hasContent = true;
        }
    
        // Check LLM response
        if (llmResponseArea.getText() != null && !llmResponseArea.getText().trim().isEmpty()) {
        hasContent = true;
        }
    
        if (hasContent) {
            int result = JOptionPane.showConfirmDialog(this,
                "Clear request, response, and AI output?\n\nPrompt will be preserved.",
                "Confirm Clear",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE);
        
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }
    
        // Clear internal state
        currentRequest = null;
        currentResponse = null;
        currentService = null;
        currentContext = null;
    
        // Clear request editor - use empty byte array instead of null
        requestEditor.setMessage(new byte[0], true);
    
        // Clear response editor - use empty byte array instead of null
        responseEditor.setMessage(new byte[0], false);
    
        // Clear LLM response
        llmResponseArea.setText("");
    
        // Reset button states
        sendToLlmBtn.setText("Send to LLM");
        sendToLlmBtn.setEnabled(true);
        sendToServerBtn.setText("Send to Server");
        sendToServerBtn.setEnabled(true);
    
        // Optional: Show success message
        state.getStdout().println("Cleared all content");
}

    private void renderResponse() {
        responseEditor.setMessage(currentResponse, false);
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

    // ================= ITab =================

    @Override
    public String getTabCaption() {
        return "Suite-o-llama";
    }

    @Override
    public Component getUiComponent() {
        return this;
    }


    // ================= Public Entry =================

    public void loadRequest(IHttpRequestResponse message) {
    currentService = message.getHttpService();
    currentRequest = message.getRequest();
    currentResponse = message.getResponse();

    requestEditor.setMessage(currentRequest, true);
    responseEditor.setMessage(currentResponse, false);

    currentContext = AutocompleteContext.from(message);
}
    // to load only request not response in the main tab

    public void loadRequestOnly(byte[] request, IHttpService service) {
    currentService = service;
    currentRequest = request;
    currentResponse = null;  // Clear any existing response
    currentContext = null;   // Clear context since no message
    
    requestEditor.setMessage(currentRequest, true);
    responseEditor.setMessage(null, false);  // Clear response editor
    llmResponseArea.setText("");  // Clear LLM response
    
    // Note: We can't create AutocompleteContext without IHttpRequestResponse
    // So currentContext remains null
}
}
