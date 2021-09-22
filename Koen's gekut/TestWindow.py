import tkinter as tk

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
)
button.pack()
window.mainloop()