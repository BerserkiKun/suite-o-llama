package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.*;
import java.util.HashMap;
import java.util.Map;
import java.awt.datatransfer.*;
import java.awt.dnd.*;

public class TabManager extends JPanel implements ITab {
    private final ExtensionState state;
    private final PromptEngine promptEngine;
    
    // Core UI Components
    private JTabbedPane tabbedPane;
    private JButton newTabButton;
    private JPopupMenu tabContextMenu;
    private JMenuItem closeTabMenuItem;
    private JMenuItem closeOtherTabsMenuItem;
    private JMenuItem closeAllTabsMenuItem;
    private JMenuItem renameTabMenuItem;
    
    // State Management
    private int tabCounter = 1;
    private Map<Component, String> tabOriginalNames = new HashMap<>();
    private int lastRightClickedTabIndex = -1;
    
    private final Object tabReuseLock = new Object(); // NEW: For thread safety

    public TabManager(ExtensionState state, PromptEngine PromptEngineParam) {
        this.state = state;
        this.promptEngine = PromptEngineParam;
        
        initUI();
        createNewTab(); // Create first tab
    }
    
    private void initUI() {
        setLayout(new BorderLayout());
        setBorder(new EmptyBorder(5, 5, 5, 5));
        
        // Create tabbed pane with Repeater-style configuration
        tabbedPane = new JTabbedPane(JTabbedPane.TOP, JTabbedPane.SCROLL_TAB_LAYOUT);
        tabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
        
        // ENABLE DRAG-AND-DROP REORDERING
        enableTabReordering();

        // Tab change listener for UI updates
        tabbedPane.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                updateUIForCurrentTab();
            }
        });
        
        // Mouse listener for tab right-click context menu
        tabbedPane.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int tabIndex = tabbedPane.indexAtLocation(e.getX(), e.getY());
                    if (tabIndex >= 0) {
                        lastRightClickedTabIndex = tabIndex;
                        tabbedPane.setSelectedIndex(tabIndex);
                        showTabContextMenu(e.getX(), e.getY());
                    }
                }
            }
        });
        
        // Double-click to rename tab
        tabbedPane.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int tabIndex = tabbedPane.indexAtLocation(e.getX(), e.getY());
                    if (tabIndex >= 0) {
                        renameTab(tabIndex);
                    }
                }
            }
        });
        
        // Initialize context menu
        initTabContextMenu();
        
        // Create and add the "+" button as the first tab (like Burp)
        newTabButton = createNewTabButton();
        tabbedPane.addTab("", null); // Empty tab for the button
        tabbedPane.setTabComponentAt(0, newTabButton);
        
        add(tabbedPane, BorderLayout.CENTER);
    }
    
    private JButton createNewTabButton() {
        JButton button = new JButton("+");
        button.setFont(new Font("Arial", Font.BOLD, 14));
        button.setMargin(new Insets(2, 8, 2, 8));
        button.setToolTipText("Create new tab");
        button.setFocusPainted(false);
        
        button.addActionListener(e -> createNewTab());
        
        return button;
    }
    
    private void enableTabReordering() {
        // Create a single listener instance that maintains state
        TabDragListener dragListener = new TabDragListener();
        tabbedPane.addMouseListener(dragListener);
        tabbedPane.addMouseMotionListener(dragListener);
    }

    private class TabDragListener extends MouseAdapter {
        // Track which tab we started dragging
        private int dragStartIndex = -1;
        
        // Store where mouse was initially pressed (to calculate drag distance)
        private Point pressPoint = null;
        
        // Flag to indicate if we're currently in a drag operation
        private boolean isDragging = false;
        
        @Override
        public void mousePressed(MouseEvent e) {
            // Only respond to left mouse button clicks
            if (SwingUtilities.isLeftMouseButton(e)) {
                // Find which tab was clicked (if any)
                dragStartIndex = tabbedPane.indexAtLocation(e.getX(), e.getY());
                
                // Store the exact click location for later distance calculation
                pressPoint = e.getPoint();
                
                // Reset drag flag - we're not dragging yet, just clicked
                isDragging = false;
                
                // The "+" button is a special tab used to create new tabs
                if (dragStartIndex >= tabbedPane.getTabCount() - 1) {
                    dragStartIndex = -1;  // Invalid index means don't process this click
                }
            }
        }
        
        @Override
        public void mouseDragged(MouseEvent e) {
            // If no valid drag start or no initial click point, do nothing
            if (dragStartIndex == -1 || pressPoint == null) return;
            
            // Calculate how far mouse has moved from original click point
            // This prevents accidental drags from tiny mouse movements
            double distance = pressPoint.distance(e.getPoint());
            
            // If mouse moved more than 5 pixels and we're not already dragging,
            // start a drag operation
            if (distance > 5 && !isDragging) {
                isDragging = true;
                
                // Change cursor to "move" cursor to give visual feedback
                // This tells user they're in drag mode
                tabbedPane.setCursor(Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR));
            }
            
            // If we're now in drag mode, handle the dragging
            if (isDragging) {
                // Find which tab the mouse is currently over
                int currentIndex = tabbedPane.indexAtLocation(e.getX(), e.getY());
                
                // Don't allow dragging onto the "+" button (last tab)
                // The "+" button is always at the end for creating new tabs
                if (currentIndex >= tabbedPane.getTabCount() - 1) {
                    return;  // Skip further processing
                }
                
                // Handle auto-scrolling when dragging near tab pane edges
                // This allows users to drag tabs beyond visible area
                autoScrollDuringDrag(e.getX());
            }
        }
        
        @Override
        public void mouseReleased(MouseEvent e) {
            // Only process if we were actually dragging a valid tab
            if (isDragging && dragStartIndex != -1) {
                // Find where the tab was dropped
                int dropIndex = tabbedPane.indexAtLocation(e.getX(), e.getY());
                
                // Valid drop conditions:
                // 1. Must be a valid tab index (not -1)
                // 2. Can't drop on "+" button (last tab is for creating new tabs)
                // 3. Can't drop on the same tab we started from (no point)
                if (dropIndex >= 0 && dropIndex < tabbedPane.getTabCount() - 1 && 
                    dropIndex != dragStartIndex) {
                    
                    // This is the key method that actually reorders tabs
                    // It physically moves the tab from dragStartIndex to dropIndex
                    reorderTab(dragStartIndex, dropIndex);
                }
            }
            
            // ----- CLEANUP PHASE: Reset everything for next drag -----
            
            // Reset drag start index - ready for next operation
            dragStartIndex = -1;
            
            // Clear the stored click point
            pressPoint = null;
            
            // We're no longer dragging
            isDragging = false;
            
            // Restore default cursor (arrow instead of move cursor)
            tabbedPane.setCursor(Cursor.getDefaultCursor());
        }
        
        /**
         * Auto-scrolls tabs when user drags near the edges of the tab pane.
         * This allows dragging tabs beyond the visible area without losing control.
         * 
         * @param mouseX The current X coordinate of mouse pointer
         */
        private void autoScrollDuringDrag(int mouseX) {
            int width = tabbedPane.getWidth();  // Get total width of tab pane
            int selectedIndex = tabbedPane.getSelectedIndex();  // Currently selected tab
            
            // If mouse is within 50 pixels of left edge and there are tabs to the left
            if (mouseX < 50 && selectedIndex > 0) {
                // Scroll left by selecting the previous tab
                tabbedPane.setSelectedIndex(selectedIndex - 1);
            }
            // If mouse is within 50 pixels of right edge and there are tabs to the right
            // Note: -2 because last tab is "+" button and we don't want to select it
            else if (mouseX > width - 50 && selectedIndex < tabbedPane.getTabCount() - 2) {
                // Scroll right by selecting the next tab
                tabbedPane.setSelectedIndex(selectedIndex + 1);
            }
        }
    }

    private void reorderTab(int sourceIndex, int targetIndex) {
        if (sourceIndex < 0 || targetIndex < 0 || 
            sourceIndex >= tabbedPane.getTabCount() - 1 || 
            targetIndex >= tabbedPane.getTabCount() - 1 ||
            sourceIndex == targetIndex) {
            return;
        }
        
        try {
            // Store all tab properties
            Component tabComponent = tabbedPane.getComponentAt(sourceIndex);
            Component tabHeader = tabbedPane.getTabComponentAt(sourceIndex);
            String title = getTabTitle(sourceIndex);
            Icon icon = tabbedPane.getIconAt(sourceIndex);
            String tooltip = tabbedPane.getToolTipTextAt(sourceIndex);
            boolean isEnabled = tabbedPane.isEnabledAt(sourceIndex);
            
            // IMPORTANT: Remove the tab
            tabbedPane.removeTabAt(sourceIndex);
            
            // Adjust target index if source was before target
            int adjustedTarget = targetIndex;
            if (sourceIndex < targetIndex) {
                adjustedTarget = targetIndex - 1;
            }
            
            // Insert at new position
            tabbedPane.insertTab(title, icon, tabComponent, tooltip, adjustedTarget);
            tabbedPane.setEnabledAt(adjustedTarget, isEnabled);
            
            // Restore tab component (with close button)
            if (tabHeader != null) {
                tabbedPane.setTabComponentAt(adjustedTarget, tabHeader);
            }
            
            // Select the moved tab
            tabbedPane.setSelectedIndex(adjustedTarget);
            
            state.getStdout().println("[TabManager] Tab reordered: " + 
                                    sourceIndex + " → " + adjustedTarget);
            
        } catch (Exception e) {
            state.getStderr().println("[TabManager] Error reordering tab: " + e.getMessage());
            e.printStackTrace(state.getStderr());
        }
    }

    private void autoScrollOnDrag(int mouseX) {
        int width = tabbedPane.getWidth();
        
        // Auto-scroll left if near left edge
        if (mouseX < 50 && tabbedPane.getSelectedIndex() > 0) {
            int newIndex = Math.max(0, tabbedPane.getSelectedIndex() - 1);
            tabbedPane.setSelectedIndex(newIndex);
        }
        // Auto-scroll right if near right edge
        else if (mouseX > width - 50 && tabbedPane.getSelectedIndex() < tabbedPane.getTabCount() - 2) {
            int newIndex = Math.min(tabbedPane.getTabCount() - 2, tabbedPane.getSelectedIndex() + 1);
            tabbedPane.setSelectedIndex(newIndex);
        }
    }

    private void initTabContextMenu() {
        tabContextMenu = new JPopupMenu();
        
        closeTabMenuItem = new JMenuItem("Close tab");
        closeTabMenuItem.addActionListener(e -> closeTab(lastRightClickedTabIndex));
        
        closeOtherTabsMenuItem = new JMenuItem("Close other tabs");
        closeOtherTabsMenuItem.addActionListener(e -> closeOtherTabs(lastRightClickedTabIndex));
        
        closeAllTabsMenuItem = new JMenuItem("Close all tabs");
        closeAllTabsMenuItem.addActionListener(e -> closeAllTabs());
        
        renameTabMenuItem = new JMenuItem("Rename tab");
        renameTabMenuItem.addActionListener(e -> renameTab(lastRightClickedTabIndex));
        
        tabContextMenu.add(closeTabMenuItem);
        tabContextMenu.add(closeOtherTabsMenuItem);
        tabContextMenu.add(closeAllTabsMenuItem);
        tabContextMenu.addSeparator();
        tabContextMenu.add(renameTabMenuItem);
    }
    
    private void showTabContextMenu(int x, int y) {
        lastRightClickedTabIndex = tabbedPane.indexAtLocation(x, y);
    
        if (lastRightClickedTabIndex < 0 || lastRightClickedTabIndex >= tabbedPane.getTabCount() - 1) {
            return;
        }
        // Enable/disable menu items based on context
        int totalTabs = tabbedPane.getTabCount() - 1; // Exclude "+" button
        
        closeOtherTabsMenuItem.setEnabled(totalTabs > 1);
        closeAllTabsMenuItem.setEnabled(totalTabs > 0);
        
        tabContextMenu.show(tabbedPane, x, y);
    }
    
    private void createNewTab() {
        SwingUtilities.invokeLater(() -> {
            MainTabPanel panel = new MainTabPanel(state, promptEngine);
            String tabName = generateTabName();
            
            // Add before the "+" button
            int insertPosition = tabbedPane.getTabCount() - 1;
            tabbedPane.insertTab(tabName, null, panel, null, insertPosition);
            
            // Create tab component with close button
            JPanel tabComponent = createTabComponent(tabName, panel);
            tabbedPane.setTabComponentAt(insertPosition, tabComponent);
            
            // Store original name
            tabOriginalNames.put(panel, tabName);
            
            // Select the new tab
            tabbedPane.setSelectedIndex(insertPosition);
            
            state.getStdout().println("Created new tab: " + tabName);

            // ========== NEW: Track if this is the initial empty tab ==========
            // Marking it by setting a special property on the panel
            panel.setInitialEmptyTab(true);
        });
    }
    
    private boolean isInitialEmptyTab(MainTabPanel panel) {
        if (panel == null) return false;
        
        // Check if panel is completely empty (no request, response, or LLM content)
        return !panel.hasContent();
    }

    private String generateTabName() {
        return "Tab " + tabCounter++;
    }
    
    private JPanel createTabComponent(String title, MainTabPanel panel) {
        JPanel tabPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        tabPanel.setOpaque(false);
        
        JLabel titleLabel = new JLabel(title);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));
        
        JButton closeButton = new JButton("×");
        closeButton.setFont(new Font("Arial", Font.BOLD, 14));
        closeButton.setMargin(new Insets(0, 5, 0, 5));
        closeButton.setBorderPainted(false);
        closeButton.setContentAreaFilled(false);
        closeButton.setFocusPainted(false);
        closeButton.setToolTipText("Close tab");
        closeButton.setForeground(Color.GRAY);
        
        // Hover effects
        closeButton.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                closeButton.setForeground(Color.RED);
                closeButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            }
            
            @Override
            public void mouseExited(MouseEvent e) {
                closeButton.setForeground(Color.GRAY);
                closeButton.setCursor(Cursor.getDefaultCursor());
            }
        });
        
        // Close button action
        closeButton.addActionListener(e -> {
            int tabIndex = getTabIndexForComponent(panel);
            if (tabIndex != -1) {
                closeTabWithConfirmation(tabIndex);
            }
        });
        
        tabPanel.add(titleLabel);
        tabPanel.add(closeButton);
        
        return tabPanel;
    }
    
    private int getTabIndexForComponent(Component component) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if (tabbedPane.getComponentAt(i) == component) {
                return i;
            }
        }
        return -1;
    }
    
    public void loadRequestInSmartTab(byte[] request, IHttpService service) {
        SwingUtilities.invokeLater(() -> {
            synchronized (tabReuseLock) {
                // First, check ALL existing tabs (excluding "+" button) for initial empty tab
                for (int i = 0; i < tabbedPane.getTabCount() - 1; i++) {
                    Component comp = tabbedPane.getComponentAt(i);
                    if (comp instanceof MainTabPanel) {
                        MainTabPanel tab = (MainTabPanel) comp;
                        
                        // If this is an initial empty tab, reuse it
                        if (tab.isInitialEmptyTab()) {
                            tab.loadRequestOnly(request, service);
                            updateTabName(tab, generateSmartName(request, service));
                            
                            // Clear the initial empty tab flag since it's now populated
                            tab.setInitialEmptyTab(false);
                            
                            // Select this tab
                            tabbedPane.setSelectedIndex(i);
                            
                            state.getStdout().println("Reused initial empty tab for request");
                            return; // Exit - we've used the initial empty tab
                        }
                    }
                }
                
                // If no initial empty tab found, check current tab for emptiness
                MainTabPanel currentTab = getActiveTab();
                if (currentTab != null && !currentTab.hasContent()) {
                    // Reuse empty tab (but not initial empty tab)
                    currentTab.loadRequestOnly(request, service);
                    updateTabName(currentTab, generateSmartName(request, service));
                    state.getStdout().println("Reused empty tab for request");
                } else {
                    // Create new tab
                    loadRequestInNewTab(request, service);
                }
            }
        });
    }

    private String generateSmartName(byte[] request, IHttpService service) {
        if (service == null) {
            return "Request";
        }
        
        try {
            IRequestInfo reqInfo = state.getHelpers().analyzeRequest(service, request);
            String method = reqInfo.getMethod();
            String path = reqInfo.getUrl().getPath();
            
            // Truncate long paths
            if (path.length() > 30) {
                path = path.substring(0, 27) + "...";
            }
            
            return method + " " + path;
            
        } catch (Exception e) {
            return service.getHost();
        }
    }

    private void closeTabWithConfirmation(int tabIndex) {
        /*
        // this code is commented out close there is no requiremnt of comfirmation box on closing tabs.
        if (tabIndex < 0 || tabIndex >= tabbedPane.getTabCount() - 1) return;
        
        Component tabComponent = tabbedPane.getComponentAt(tabIndex);
        if (tabComponent instanceof MainTabPanel) {
            MainTabPanel panel = (MainTabPanel) tabComponent;
            
            if (panel.hasContent()) {
                String tabName = getTabTitle(tabIndex);
                int result = JOptionPane.showConfirmDialog(this,
                    "Close tab '" + tabName + "'?\n\nUnsaved work will be lost.",
                    "Confirm Close",
                    JOptionPane.YES_NO_OPTION,
                    JOptionPane.WARNING_MESSAGE);
                
                if (result != JOptionPane.YES_OPTION) {
                    return;
                }
            }*/
            
            closeTab(tabIndex);
        //} // Also commented curly brackaets
    }
    
    private void closeTab(int tabIndex) {
        if (tabIndex < 0 || tabIndex >= tabbedPane.getTabCount() - 1) return;
        
        Component tabComponent = tabbedPane.getComponentAt(tabIndex);
        String tabName = getTabTitle(tabIndex);
        
        // Clean up resources
        if (tabComponent instanceof MainTabPanel) {
            MainTabPanel panel = (MainTabPanel) tabComponent;
            tabOriginalNames.remove(panel);
            // Note: MainTabPanel doesn't have explicit cleanup, but could add if needed
        }
        
        tabbedPane.remove(tabIndex);
        state.getStdout().println("Closed tab: " + tabName);
        
        // Ensure at least one tab remains (excluding "+" button)
        if (tabbedPane.getTabCount() == 1) { // Only "+" button remains
            createNewTab();
        }
    }
    
    private void closeOtherTabs(int keepIndex) {
        if (keepIndex < 0) return;
        
        int totalTabs = tabbedPane.getTabCount() - 1; // Exclude "+" button
        
        // Count tabs with content to warn user
        int tabsWithContent = 0;
        for (int i = 0; i < totalTabs; i++) {
            if (i != keepIndex) {
                Component comp = tabbedPane.getComponentAt(i);
                if (comp instanceof MainTabPanel && ((MainTabPanel) comp).hasContent()) {
                    tabsWithContent++;
                }
            }
        }
        
        if (tabsWithContent > 0) {
            int result = JOptionPane.showConfirmDialog(this,
                "Close " + (totalTabs - 1) + " other tabs?\n\n" +
                tabsWithContent + " tab(s) contain unsaved work.",
                "Confirm Close Others",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
            
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }
        
        // Close tabs from right to left to avoid index shifting issues
        for (int i = totalTabs - 1; i >= 0; i--) {
            if (i != keepIndex) {
                closeTab(i);
            }
        }
    }
    
    private void closeAllTabs() {
        int totalTabs = tabbedPane.getTabCount() - 1; // Exclude "+" button
        
        if (totalTabs == 0) return;
        
        // Count tabs with content
        int tabsWithContent = 0;
        for (int i = 0; i < totalTabs; i++) {
            Component comp = tabbedPane.getComponentAt(i);
            if (comp instanceof MainTabPanel && ((MainTabPanel) comp).hasContent()) {
                tabsWithContent++;
            }
        }
        
        if (tabsWithContent > 0) {
            int result = JOptionPane.showConfirmDialog(this,
                "Close all " + totalTabs + " tabs?\n\n" +
                tabsWithContent + " tab(s) contain unsaved work.",
                "Confirm Close All",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
            
            if (result != JOptionPane.YES_OPTION) {
                return;
            }
        }
        
        // Close all tabs from right to left
        for (int i = totalTabs - 1; i >= 0; i--) {
            closeTab(i);
        }
    }
    
    private void renameTab(int tabIndex) {
        if (tabIndex < 0 || tabIndex >= tabbedPane.getTabCount() - 1) return;
        
        String currentName = getTabTitle(tabIndex);
        String newName = JOptionPane.showInputDialog(this,
            "Enter new tab name:",
            "Rename Tab",
            JOptionPane.QUESTION_MESSAGE,
            null,
            null,
            currentName).toString();
        
        if (newName != null && !newName.trim().isEmpty() && !newName.equals(currentName)) {
            Component tabComponent = tabbedPane.getComponentAt(tabIndex);
            JPanel tabPanel = (JPanel) tabbedPane.getTabComponentAt(tabIndex);
            
            if (tabPanel != null) {
                // Update the label in the tab component
                Component[] comps = tabPanel.getComponents();
                if (comps.length > 0 && comps[0] instanceof JLabel) {
                    ((JLabel) comps[0]).setText(newName);
                }
                
                // Store the new name
                if (tabComponent instanceof MainTabPanel) {
                    tabOriginalNames.put(tabComponent, newName);
                }
                
                state.getStdout().println("Renamed tab to: " + newName);
            }
        }
    }
    
    private String getTabTitle(int tabIndex) {
        if (tabIndex < 0 || tabIndex >= tabbedPane.getTabCount()) {
            return "";
        }
        
        Component tabComp = tabbedPane.getTabComponentAt(tabIndex);
        if (tabComp instanceof JPanel) {
            JPanel tabPanel = (JPanel) tabComp;
            Component[] comps = tabPanel.getComponents();
            if (comps.length > 0 && comps[0] instanceof JLabel) {
                return ((JLabel) comps[0]).getText();
            }
        }
        
        // Fallback to JTabbedPane title
        return tabbedPane.getTitleAt(tabIndex);
    }
    
    private void updateUIForCurrentTab() {
    }
    
    // Public API methods for external integration
    
    public void loadRequestInNewTab(byte[] request, IHttpService service) {
        createNewTab();
        
        SwingUtilities.invokeLater(() -> {
            MainTabPanel currentTab = getActiveTab();
            if (currentTab != null) {
                currentTab.loadRequestOnly(request, service);
                
                // IMPORTANT: Clear the initial empty tab flag for newly created tabs
                currentTab.setInitialEmptyTab(false);

                // Use smart naming instead of just "Req: host"
                String tabName = generateSmartName(request, service);
                updateTabName(currentTab, tabName);
            }
        });
    }
    
    public void loadRequestOnly(byte[] request, IHttpService service) {
        SwingUtilities.invokeLater(() -> {
            MainTabPanel currentTab = getActiveTab();
            if (currentTab != null) {
                currentTab.loadRequestOnly(request, service);
                
                // Update tab name based on request
                if (service != null) {
                    String host = service.getHost();
                    updateTabName(currentTab, "Req: " + host);
                }
            }
        });
    }
    
    private void updateTabName(MainTabPanel panel, String newName) {
        int tabIndex = getTabIndexForComponent(panel);
        if (tabIndex != -1) {
            Component tabComp = tabbedPane.getTabComponentAt(tabIndex);
            if (tabComp instanceof JPanel) {
                JPanel tabPanel = (JPanel) tabComp;
                Component[] comps = tabPanel.getComponents();
                if (comps.length > 0 && comps[0] instanceof JLabel) {
                    ((JLabel) comps[0]).setText(newName);
                }
            }
        }
    }
    
    public MainTabPanel getActiveTab() {
        int selectedIndex = tabbedPane.getSelectedIndex();
        if (selectedIndex >= 0 && selectedIndex < tabbedPane.getTabCount() - 1) {
            Component comp = tabbedPane.getComponentAt(selectedIndex);
            if (comp instanceof MainTabPanel) {
                return (MainTabPanel) comp;
            }
        }
        return null;
    }
    
    public int getTabCount() {
        return tabbedPane.getTabCount() - 1; // Exclude "+" button
    }
    
    @Override
    public String getTabCaption() {
        return "Suite-o-llama";
    }
    
    @Override
    public Component getUiComponent() {
        return this;
    }
}