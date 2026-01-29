package burp;

public class MessageEditorTabFactory implements IMessageEditorTabFactory {
    private final ExtensionState state;
    
    public MessageEditorTabFactory(ExtensionState state) {
        this.state = state;
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        // ALWAYS CREATE NEW INSTANCES - never reuse
        if (editable) {
            return new RepeaterAITab(state, controller);
        } else {
            return new RepeaterAIResponseTab(state, controller);
        }
    }
}