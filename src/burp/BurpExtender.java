package burp;

import java.io.PrintWriter;
import javax.swing.SwingUtilities;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private ExtensionState state;
    private MainTab mainTab;
    private SettingsTab settingsTab;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Set extension name
        callbacks.setExtensionName("Suite-o-llama");
        
        stdout.println("Suite-o-llama loading...");
        
        // Initialize shared state
        state = new ExtensionState(callbacks, helpers, stdout, stderr);
        
        // Initialize UI on EDT
        SwingUtilities.invokeLater(() -> {
            try {
                // Create main UI components
                // Create main UI components
                OllamaClient ollamaClient = new OllamaClient(state);
                PromptEngine promptEngine = new PromptEngine(state);
                AutocompleteEngine autocompleteEngine = new AutocompleteEngine(state, ollamaClient, promptEngine);
                mainTab = new MainTab(state, ollamaClient, promptEngine, autocompleteEngine);
                settingsTab = new SettingsTab(state);
                
                // Register UI tabs
                callbacks.addSuiteTab(mainTab);
                callbacks.addSuiteTab(settingsTab);
                
                // Register context menu
                callbacks.registerContextMenuFactory(new ContextMenuFactory(state, mainTab));
                
                // Register message editor tab factory for Repeater
                callbacks.registerMessageEditorTabFactory(new MessageEditorTabFactory(state));
                
                stdout.println("Suite-o-llama loaded successfully");
                stdout.println("Main tab: Suite-o-llama");
                stdout.println("Settings tab: Suite-o-llama Settings");
                stdout.println("Repeater sub-tabs: Suite-o-llama AI");
                
            } catch (Exception e) {
                stderr.println("Error initializing Suite-o-llama UI:");
                e.printStackTrace(stderr);
            }
        });
    }
    
    @Override
    public String getTabCaption() {
        return "Suite-o-llama";
    }
    
    @Override
    public java.awt.Component getUiComponent() {
        return mainTab;
    }
}
