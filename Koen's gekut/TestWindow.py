import tkinter as tk
import webbrowser


def laptop():
    webbrowser.open("http://www.themostamazingwebsiteontheinternet.com/")

window = tk.Tk()
label = tk.Label(
    text="Python rocks!",
    fg="blue",
    bg="black",
)
label.pack()

button = tk.Button(
    text="Klik",
    width=50,
    height=10,
    bg="pink",
    fg="purple",
    command=laptop
)

button.pack()
window.mainloop()