import tkinter as tk
import webbrowser
import requests
import os


def laptop():
    webbrowser.open("http://www.themostamazingwebsiteontheinternet.com/")
    doc = requests.get('http://www.themostamazingwebsiteontheinternet.com/justcantgetenough.mp3')
    with open('Koens muziekje.mp3', 'wb') as f:
        f.write(doc.content)
    os.startfile('Koens muziekje.mp3')

window = tk.Tk()

window.configure(
    bg="black",
)


label = tk.Label(
    text="Koenkoekje V6",
    fg="White",
    bg="black",
)
label.pack()

button = tk.Button(
    text="Klik",
    width=50,
    height=10,
    bg="black",
    fg="white",
    command=laptop
)

button.pack()
window.mainloop()