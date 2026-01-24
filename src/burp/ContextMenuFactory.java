package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

public class ContextMenuFactory implements IContextMenuFactory {
    private final ExtensionState state;
    private final MainTab mainTab;
    
    public ContextMenuFactory(ExtensionState state, MainTab mainTab) {
        this.state = state;
        this.mainTab = mainTab;
    }
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages == null || messages.length == 0) {
            return menuItems;
        }
        
        JMenuItem sendToSuiteOLlama = new JMenuItem("Send to Suite-o-llama");
        sendToSuiteOLlama.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToMainTab(messages[0]);
            }
        });
        
        menuItems.add(sendToSuiteOLlama);
        return menuItems;
    }
    
    private void sendToMainTab(IHttpRequestResponse message) {
    if (message == null) {
        return;
    }
    
    // Get only the request, not response
    byte[] request = message.getRequest();
    IHttpService service = message.getHttpService();
    
    if (request == null || service == null) {
        return;
    }
    
    SwingUtilities.invokeLater(() -> {
        // Load ONLY the request (not response)
        mainTab.loadRequestOnly(request, service);
        state.getStdout().println("Request sent to Suite-o-llama from context menu");
    });
}
}