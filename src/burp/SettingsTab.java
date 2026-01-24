package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;

public class SettingsTab extends JPanel implements ITab {
    private final ExtensionState state;
    private OllamaClient testClient;
    
    // UI Components
    private JTextField endpointField;
    private JTextField analysisModelField;
    private JTextField payloadModelField;
    private JSpinner temperatureSpinner;
    private JSpinner maxTokensSpinner;
    private JSpinner maxContextSpinner;
    private JCheckBox redactAuthCheckbox;
    private JCheckBox redactCookiesCheckbox;
    private JButton saveButton;
    private JButton testConnectionButton;
    private JTextArea statusArea;
    private JList<String> modelList;
    private DefaultListModel<String> modelListModel;
    
    public SettingsTab(ExtensionState state) {
        this.state = state;
        this.testClient = new OllamaClient(state);
        initUI();
        loadSettings();
    }
    
    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        setBorder(new EmptyBorder(10, 10, 10, 10));
        
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        
        // Ollama Connection Settings
        JPanel connectionPanel = new JPanel(new GridBagLayout());
        connectionPanel.setBorder(BorderFactory.createTitledBorder("Ollama Connection"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0;
        connectionPanel.add(new JLabel("Endpoint:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        endpointField = new JTextField(30);
        connectionPanel.add(endpointField, gbc);
        
        gbc.gridx = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        testConnectionButton = new JButton("Test Connection");
        testConnectionButton.addActionListener(e -> testConnection());
        connectionPanel.add(testConnectionButton, gbc);
        
        connectionPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 
                                                     connectionPanel.getPreferredSize().height + 20));
        mainPanel.add(connectionPanel);
        mainPanel.add(Box.createVerticalStrut(10));
        
        // Model Settings
        JPanel modelPanel = new JPanel(new GridBagLayout());
        modelPanel.setBorder(BorderFactory.createTitledBorder("Model Configuration"));
        gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        gbc.gridx = 0; gbc.gridy = 0;
        modelPanel.add(new JLabel("Analysis Model:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        analysisModelField = new JTextField(25);
        modelPanel.add(analysisModelField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        modelPanel.add(new JLabel("Payload Model:"), gbc);
        
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        payloadModelField = new JTextField(25);
        modelPanel.add(payloadModelField, gbc);
        
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0;
        modelPanel.add(new JLabel("Temperature:"), gbc);
        
        gbc.gridx = 1;
        temperatureSpinner = new JSpinner(new SpinnerNumberModel(0.7, 0.0, 2.0, 0.1));
        modelPanel.add(temperatureSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 3;
        modelPanel.add(new JLabel("Max Tokens:"), gbc);
        
        gbc.gridx = 1;
        maxTokensSpinner = new JSpinner(new SpinnerNumberModel(4096, 128, 16384, 256));
        modelPanel.add(maxTokensSpinner, gbc);
        
        gbc.gridx = 0; gbc.gridy = 4;
        modelPanel.add(new JLabel("Max Context Size:"), gbc);
        
        gbc.gridx = 1;
        maxContextSpinner = new JSpinner(new SpinnerNumberModel(16384, 1024, 65536, 1024));
        JPanel contextPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        contextPanel.add(maxContextSpinner);
        contextPanel.add(new JLabel("characters"));
        modelPanel.add(contextPanel, gbc);
        
        modelPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 
                                                modelPanel.getPreferredSize().height + 20));
        mainPanel.add(modelPanel);
        mainPanel.add(Box.createVerticalStrut(10));
        
        // Security Settings
        JPanel securityPanel = new JPanel(new GridBagLayout());
        securityPanel.setBorder(BorderFactory.createTitledBorder("Security & Privacy"));
        gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 0; gbc.gridy = 0;
        
        redactAuthCheckbox = new JCheckBox("Redact Authorization headers");
        securityPanel.add(redactAuthCheckbox, gbc);
        
        gbc.gridy = 1;
        redactCookiesCheckbox = new JCheckBox("Redact Cookies");
        securityPanel.add(redactCookiesCheckbox, gbc);
        
        gbc.gridy = 2;
        JLabel note = new JLabel("<html><i>Redacted data will be replaced with [REDACTED] before sending to LLM</i></html>");
        note.setFont(note.getFont().deriveFont(Font.PLAIN, 10f));
        securityPanel.add(note, gbc);
        
        securityPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 
                                                   securityPanel.getPreferredSize().height + 20));
        mainPanel.add(securityPanel);
        mainPanel.add(Box.createVerticalStrut(10));
        
        // Available Models Panel
        JPanel modelsPanel = new JPanel(new BorderLayout(5, 5));
        modelsPanel.setBorder(BorderFactory.createTitledBorder("Available Models"));
        
        modelListModel = new DefaultListModel<>();
        modelList = new JList<>(modelListModel);
        JScrollPane modelScroll = new JScrollPane(modelList);
        modelScroll.setPreferredSize(new Dimension(400, 150));
        
        JButton refreshModelsBtn = new JButton("Refresh Models");
        refreshModelsBtn.addActionListener(e -> refreshModels());
        
        modelsPanel.add(modelScroll, BorderLayout.CENTER);
        modelsPanel.add(refreshModelsBtn, BorderLayout.SOUTH);
        
        modelsPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 200));
        mainPanel.add(modelsPanel);
        mainPanel.add(Box.createVerticalStrut(10));
        
        // Save button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        saveButton = new JButton("Save Settings");
        saveButton.addActionListener(e -> saveSettings());
        buttonPanel.add(saveButton);
        
        JButton resetButton = new JButton("Reset to Defaults");
        resetButton.addActionListener(e -> resetToDefaults());
        buttonPanel.add(resetButton);
        
        buttonPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
        mainPanel.add(buttonPanel);
        
        // Status area
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBorder(BorderFactory.createTitledBorder("Status"));
        statusArea = new JTextArea(5, 40);
        statusArea.setEditable(false);
        statusArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        statusPanel.add(new JScrollPane(statusArea), BorderLayout.CENTER);
        mainPanel.add(statusPanel);
        
        JScrollPane scrollPane = new JScrollPane(mainPanel);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        add(scrollPane, BorderLayout.CENTER);
    }
    
    private void loadSettings() {
        endpointField.setText(state.getOllamaEndpoint());
        analysisModelField.setText(state.getAnalysisModel());
        payloadModelField.setText(state.getPayloadModel());
        temperatureSpinner.setValue(state.getTemperature());
        maxTokensSpinner.setValue(state.getMaxTokens());
        maxContextSpinner.setValue(state.getMaxContextSize());
        redactAuthCheckbox.setSelected(state.isRedactAuthHeaders());
        redactCookiesCheckbox.setSelected(state.isRedactCookies());
    }
    
    private void saveSettings() {
        state.setOllamaEndpoint(endpointField.getText().trim());
        state.setAnalysisModel(analysisModelField.getText().trim());
        state.setPayloadModel(payloadModelField.getText().trim());
        state.setTemperature((Double) temperatureSpinner.getValue());
        state.setMaxTokens((Integer) maxTokensSpinner.getValue());
        state.setMaxContextSize((Integer) maxContextSpinner.getValue());
        state.setRedactAuthHeaders(redactAuthCheckbox.isSelected());
        state.setRedactCookies(redactCookiesCheckbox.isSelected());
        state.saveSettings();
        
        statusArea.setText("Settings saved successfully\n" + 
                          "Endpoint: " + state.getOllamaEndpoint() + "\n" +
                          "Analysis Model: " + state.getAnalysisModel() + "\n" +
                          "Payload Model: " + state.getPayloadModel());
        
        // Recreate test client with new settings
        testClient = new OllamaClient(state);
    }
    
    private void testConnection() {
        statusArea.setText("Testing connection to " + endpointField.getText() + "...\n");
        testConnectionButton.setEnabled(false);
        
        new Thread(() -> {
            try {
                // Create temporary client with current endpoint
                ExtensionState tempState = new ExtensionState(
                    state.getCallbacks(), state.getHelpers(), 
                    state.getStdout(), state.getStderr()
                );
                tempState.setOllamaEndpoint(endpointField.getText().trim());
                OllamaClient tempClient = new OllamaClient(tempState);
                
                boolean connected = tempClient.checkHealth();
                
                SwingUtilities.invokeLater(() -> {
                    if (connected) {
                        statusArea.append("✓ Connection successful!\n");
                        refreshModels();
                    } else {
                        statusArea.append("✗ Connection failed\n");
                        statusArea.append("Make sure Ollama is running:\n");
                        statusArea.append("  ollama serve\n");
                    }
                    testConnectionButton.setEnabled(true);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    statusArea.append("✗ Error: " + e.getMessage() + "\n");
                    testConnectionButton.setEnabled(true);
                });
            }
        }).start();
    }
    
    private void refreshModels() {
        new Thread(() -> {
            try {
                String[] models = testClient.getAvailableModels();
                SwingUtilities.invokeLater(() -> {
                    modelListModel.clear();
                    if (models.length > 0) {
                        for (String model : models) {
                            modelListModel.addElement(model);
                        }
                        statusArea.append("\nFound " + models.length + " models\n");
                    } else {
                        modelListModel.addElement("No models found");
                        statusArea.append("\nNo models found. Pull models using:\n");
                        statusArea.append("  ollama pull qwen2.5:7b-instruct\n");
                        statusArea.append("  ollama pull qwen2.5-coder:7b\n");
                    }
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    statusArea.append("Error fetching models: " + e.getMessage() + "\n");
                });
            }
        }).start();
    }
    
    private void resetToDefaults() {
        endpointField.setText("http://127.0.0.1:11434");
        analysisModelField.setText("qwen2.5:7b-instruct");
        payloadModelField.setText("qwen2.5-coder:7b");
        temperatureSpinner.setValue(0.7);
        maxTokensSpinner.setValue(state.getMaxTokens());
        maxContextSpinner.setValue(state.getMaxContextSize());
        redactAuthCheckbox.setSelected(true);
        redactCookiesCheckbox.setSelected(true);
        statusArea.setText("Settings reset to defaults (not saved yet)\n");
    }
    
    @Override
    public String getTabCaption() {
        return "Suite-o-llama Settings";
    }
    
    @Override
    public Component getUiComponent() {
        return this;
    }
}
