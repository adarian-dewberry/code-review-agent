"""
Code Review Agent - Minimal Test Version
"""
import gradio as gr

def hello(name):
    return f"Hello {name}!"

demo = gr.Interface(
    fn=hello,
    inputs=gr.Textbox(label="Name"),
    outputs=gr.Textbox(label="Greeting"),
    title="Test - If you see this, Gradio is working!"
)

if __name__ == "__main__":
    demo.launch()
