package burp;

import java.io.PrintWriter;
import javax.swing.SwingUtilities;

public class BurpExtender implements IBurpExtender, ITab {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private ExtensionState state;
    private TabManager mainTab;
    private SettingsTab settingsTab;
    public static final String VERSION = "2.2.0";

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Set extension name
        callbacks.setExtensionName("Suite-o-llama v" + VERSION);
        
        stdout.println("Suite-o-llama v" + VERSION + " loading...");
        
        // Initialize shared state
        state = new ExtensionState(callbacks, helpers, stdout, stderr);
        
        // Initialize UI on EDT
        SwingUtilities.invokeLater(() -> {
            try {
                // Create main UI components
                OllamaClient ollamaClient = new OllamaClient(state);
                PromptEngine promptEngine = new PromptEngine(state);
                AutocompleteEngine autocompleteEngine = new AutocompleteEngine(state, ollamaClient, promptEngine);
                TabManager tabManager = new TabManager(state, promptEngine);
                mainTab = tabManager; // TabManager implements ITab, so this works. EARLIER -> mainTab = new MainTab(state, ollamaClient, promptEngine, autocompleteEngine);
                settingsTab = new SettingsTab(state);
                
                // Register UI tabs
                callbacks.addSuiteTab(mainTab);
                callbacks.addSuiteTab(settingsTab);
                
                // Register context menu
                callbacks.registerContextMenuFactory(new ContextMenuFactory(state, tabManager)); // EARLIER -> callbacks.registerContextMenuFactory(new ContextMenuFactory(state, mainTab));
                
                // Register message editor tab factory for Repeater
                callbacks.registerMessageEditorTabFactory(new MessageEditorTabFactory(state));  // Kept for Repeater
                
                stdout.println("Suite-o-llama v" + VERSION + " loaded successfully");
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
