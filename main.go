package main

import (
	"context"
	"log"
	"types"

	"github.com/scode2023/micloud/cloud"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	// Create a new Fyne application
	myApp := app.New()
	myApp.Settings().SetTheme(theme.LightTheme()) // Use light theme

	// Create a new window
	myWindow := myApp.NewWindow("Login")

	// Create login form components
	title := widget.NewLabelWithStyle("Login", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	subtitle := widget.NewLabelWithStyle("Please enter your username and password", fyne.TextAlignCenter, fyne.TextStyle{})
	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")
	countryEntry := widget.NewEntry()
	countryEntry.SetPlaceHolder("Country")

	// Login button handler
	loginButton := widget.NewButton("Login", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		country := countryEntry.Text

		client := cloud.New(country, username, password)
		if err := client.Login(context.Background()); err != nil {
			log.Println("Failed to login:", err)
			return
		}

		showMainContent(myWindow, client)
	})

	// Create login form layout
	loginForm := container.NewVBox(
		title,
		subtitle,
		widget.NewSeparator(),
		widget.NewLabel("Username:"),
		usernameEntry,
		widget.NewLabel("Password:"),
		passwordEntry,
		widget.NewLabel("Country:"),
		countryEntry,
		loginButton,
	)

	// Create main window layout
	content := container.New(layout.NewVBoxLayout(),
		layout.NewSpacer(),
		container.New(layout.NewCenterLayout(), loginForm),
		layout.NewSpacer(),
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(400, 300)) // Set initial window size

	// Show the window
	myWindow.ShowAndRun()
}

// Function to display the main content after successful login
func showMainContent(window fyne.Window, client *cloud.Client) {
	devices, err := client.GetDevices(context.Background())
	if err != nil {
		log.Println("Failed to get devices:", err)
		return
	}

	// Create table to display device information
	table := widget.NewTable(
		func() (int, int) { return len(devices), 6 },
		func() fyne.CanvasObject { return widget.NewLabel("Cell") },
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			device := devices[id.Row]
			switch id.Col {
			case 0:
				cell.(*widget.Label).SetText(device.Did)
			case 1:
				cell.(*widget.Label).SetText(device.Name)
			case 2:
				cell.(*widget.Label).SetText(device.Model)
			case 3:
				cell.(*widget.Label).SetText(device.LocalIP)
			case 4:
				cell.(*widget.Label).SetText(device.Ssid)
			case 5:
				cell.(*widget.Label).SetText(device.Extra.FwVersion)
			}
		})

	// Create buttons for additional actions
	button1 := widget.NewButton("Button 1", func() { log.Println("Button 1 clicked") })
	button2 := widget.NewButton("Button 2", func() { log.Println("Button 2 clicked") })
	button3 := widget.NewButton("Button 3", func() { log.Println("Button 3 clicked") })

	// Create main content layout with table and buttons
	mainContent := container.NewVBox(
		table,
		button1,
		button2,
		button3,
	)

	// Set new content for the window
	window.SetContent(mainContent)
	window.Resize(fyne.NewSize(600, 400)) // Set new window size
}

// Function to set device properties (e.g., firmware, country, voice)
func setDeviceProperty(client *cloud.Client, deviceID string, siid, piid int, value string) error {
	properties := []*types.DeviceProperty{
		{
			DID:   deviceID,
			SIID:  siid,
			PIID:  piid,
			Value: value,
		},
	}

	if err := client.SetDeviceProperties(context.Background(), properties...); err != nil {
		return err
	}

	return nil
}
