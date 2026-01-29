package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuFactory implements IContextMenuFactory {
    private final ExtensionState state;
    private final TabManager tabManager;
    
    public ContextMenuFactory(ExtensionState state, TabManager tabManager) {
        this.state = state;
        this.tabManager = tabManager;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            return menuItems;
        }
        
        // Create menu item based on number of selected messages
        String menuText;
        if (messages.length == 1) {
            menuText = "Send to Suite-o-llama";
        } else {
            menuText = "Send " + messages.length + " requests to Suite-o-llama";
        }
        
        JMenuItem sendToSuiteOLlama = new JMenuItem(menuText);
        sendToSuiteOLlama.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToMainTab(messages);
            }
        });
        
        menuItems.add(sendToSuiteOLlama);
        return menuItems;
    }
    
    private void sendToMainTab(IHttpRequestResponse[] messages) {
        if (messages == null || messages.length == 0) {
            return;
        }
        
        // Use atomic counter to track first request in this batch
        final boolean[] firstRequestProcessed = {false};
        
        // Process each message in the array
        for (int i = 0; i < messages.length; i++) {
            final IHttpRequestResponse message = messages[i];
            if (message == null) continue;
            
            byte[] request = message.getRequest();
            IHttpService service = message.getHttpService();
            
            if (request == null || service == null) continue;
            
            final int requestIndex = i;
            
            SwingUtilities.invokeLater(() -> {
                if (requestIndex == 0) {
                    // First request in batch: try to reuse initial empty tab
                    tabManager.loadRequestInSmartTab(request, service);
                    firstRequestProcessed[0] = true;
                } else {
                    // Subsequent requests: create new tab
                    tabManager.loadRequestInNewTab(request, service);
                }
                
                state.getStdout().println("Request " + (requestIndex + 1) + " of " + messages.length + 
                                        " sent to Suite-o-llama from context menu");
            });
        }
    }
}