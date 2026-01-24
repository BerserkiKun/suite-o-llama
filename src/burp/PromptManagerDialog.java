package burp;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.*;

public class PromptManagerDialog extends JDialog {
    private final ExtensionState state;
    private JList<String> promptList;
    private DefaultListModel<String> listModel;
    private JTextArea previewArea;
    private String selectedPrompt = null;
    
    public PromptManagerDialog(JFrame parent, ExtensionState state) {
        super(parent, "Prompt Manager", true);
        this.state = state;
        
        initUI();
        loadPrompts();
        
        setSize(700, 500);
        setLocationRelativeTo(parent);
    }
    
    private void initUI() {
        setLayout(new BorderLayout(10, 10));
        ((JPanel)getContentPane()).setBorder(new EmptyBorder(10, 10, 10, 10));
        
        // Left panel: Prompt list
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        leftPanel.setBorder(BorderFactory.createTitledBorder("Saved Prompts"));
        
        listModel = new DefaultListModel<>();
        promptList = new JList<>(listModel);
        promptList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        promptList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                updatePreview();
            }
        });
        
        JScrollPane listScroll = new JScrollPane(promptList);
        listScroll.setPreferredSize(new Dimension(250, 0));
        leftPanel.add(listScroll, BorderLayout.CENTER);
        
        // List buttons
        JPanel listButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton deleteButton = new JButton("Delete");
        deleteButton.addActionListener(e -> deleteSelectedPrompt());
        listButtonPanel.add(deleteButton);
        
        leftPanel.add(listButtonPanel, BorderLayout.SOUTH);
        
        add(leftPanel, BorderLayout.WEST);
        
        // Right panel: Preview
        JPanel rightPanel = new JPanel(new BorderLayout(5, 5));
        rightPanel.setBorder(BorderFactory.createTitledBorder("Preview"));
        
        previewArea = new JTextArea();
        previewArea.setEditable(false);
        previewArea.setLineWrap(true);
        previewArea.setWrapStyleWord(true);
        previewArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        
        JScrollPane previewScroll = new JScrollPane(previewArea);
        rightPanel.add(previewScroll, BorderLayout.CENTER);
        
        add(rightPanel, BorderLayout.CENTER);
        
        // Bottom panel: Action buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        
        JButton loadButton = new JButton("Load Selected");
        loadButton.addActionListener(e -> loadSelectedPrompt());
        
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(e -> dispose());
        
        buttonPanel.add(loadButton);
        buttonPanel.add(cancelButton);
        
        add(buttonPanel, BorderLayout.SOUTH);
        
        // Double-click to load
        promptList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    loadSelectedPrompt();
                }
            }
        });
    }
    
    private void loadPrompts() {
        listModel.clear();
        for (String name : state.getSavedPrompts().keySet()) {
            listModel.addElement(name);
        }
        
        if (listModel.getSize() > 0) {
            promptList.setSelectedIndex(0);
        }
    }
    
    private void updatePreview() {
        String selected = promptList.getSelectedValue();
        if (selected != null) {
            String prompt = state.getSavedPrompts().get(selected);
            previewArea.setText(prompt != null ? prompt : "");
            previewArea.setCaretPosition(0);
        } else {
            previewArea.setText("");
        }
    }
    
    private void loadSelectedPrompt() {
        String selected = promptList.getSelectedValue();
        if (selected != null) {
            selectedPrompt = state.getSavedPrompts().get(selected);
            dispose();
        }
    }
    
    private void deleteSelectedPrompt() {
        String selected = promptList.getSelectedValue();
        if (selected != null) {
            int result = JOptionPane.showConfirmDialog(this,
                "Delete prompt '" + selected + "'?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION);
            
            if (result == JOptionPane.YES_OPTION) {
                state.removeSavedPrompt(selected);
                loadPrompts();
            }
        }
    }
    
    public String getSelectedPrompt() {
        return selectedPrompt;
    }
}
