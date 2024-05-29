package main

import (
	"context"
	"fmt"
	"image/color"
	"log"

	"github.com/scodevn2023/micloud/cloud"

	"github.com/scodevn2023/micloud/types"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	// Create a new Fyne application
	myApp := app.New()
	myApp.Settings().SetTheme(theme.LightTheme()) // Use light theme

	// Create a new window
	myWindow := myApp.NewWindow("Scode-MiHome -Zalo 0582392345")

	// Load MiHome icon
	icon := canvas.NewImageFromFile("assets/mihome.png")
	icon.FillMode = canvas.ImageFillContain
	icon.SetMinSize(fyne.NewSize(64, 64)) // Set the size of the icon
	// Set window icon
	iconResource, err := fyne.LoadResourceFromPath("assets/mihome.png")
	if err != nil {
		log.Println("Failed to load icon:", err)
	} else {
		myWindow.SetIcon(iconResource)
	}

	// Create login form components
	title := canvas.NewText("Scode- Mihome", color.RGBA{R: 0, G: 0, B: 255, A: 255}) // Blue color
	title.Alignment = fyne.TextAlignCenter
	title.TextStyle = fyne.TextStyle{Bold: true}

	subtitle := canvas.NewText("Please enter your Mihome account", color.RGBA{R: 128, G: 0, B: 128, A: 255}) // Purple color
	subtitle.Alignment = fyne.TextAlignCenter

	usernameEntry := widget.NewEntry()
	usernameEntry.SetPlaceHolder("Username")
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Password")

	// Create a combobox for country selection
	countryOptions := []string{"China", "Singapore", "Russia", "USA"}
	countryMap := map[string]string{
		"China":     "cn",
		"Singapore": "sg",
		"Russia":    "ru",
		"USA":       "us",
	}
	countrySelect := widget.NewSelect(countryOptions, func(selected string) {
		log.Println("Selected country:", selected)
	})
	countrySelect.PlaceHolder = "Select Country"

	// Login button handler
	loginButton := widget.NewButton("Go >", func() {
		username := usernameEntry.Text
		password := passwordEntry.Text
		selectedCountry := countrySelect.Selected
		countryCode, exists := countryMap[selectedCountry]
		if !exists {
			log.Println("Please select a valid country")
			showError(myWindow, "Invalid Country", "Please select a valid country")
			return
		}

		client := cloud.New(countryCode, username, password)
		if err := client.Login(context.Background()); err != nil {
			log.Println("Failed to login:", err)
			showError(myWindow, "Login Failed", err.Error())
			return
		}

		showMainContent(myWindow, client)
	})
	loginButton.Importance = widget.HighImportance // Highlight the login button

	// Create login form layout
	loginForm := container.NewVBox(
		icon, // Add the icon to the form
		title,
		subtitle,
		widget.NewSeparator(),
		usernameEntry,
		passwordEntry,
		countrySelect,
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
	myWindow.CenterOnScreen()

	// Show the window
	myWindow.ShowAndRun()
}

// Function to display the main content after successful login
func showMainContent(window fyne.Window, client *cloud.Client) {
	devices, err := client.GetDevices(context.Background())
	if err != nil {
		log.Println("Failed to get devices:", err)
		showError(window, "Failed to Get Devices", err.Error())
		return
	}

	// Create a container to hold the device cards
	deviceContainer := container.New(layout.NewVBoxLayout())

	// Create device cards
	for _, device := range devices {
		card := createDeviceCard(device, client)
		deviceContainer.Add(card)
	}

	// Set new content for the window
	window.SetContent(container.NewScroll(deviceContainer))
	window.Resize(fyne.NewSize(580, 320)) // Set new window size
	window.CenterOnScreen()
}

// Function to create a device card
func createDeviceCard(device *cloud.DeviceInfo, client *cloud.Client) fyne.CanvasObject {
	// Create labels for device information
	deviceIDLabel := widget.NewLabel("Device ID: " + device.Did)
	modelLabel := widget.NewLabel("Model: " + device.Model)
	localIPLabel := widget.NewLabel("Local IP: " + device.LocalIP)
	firmwareVersionLabel := widget.NewLabel("Firmware Version: " + device.Extra.FwVersion)

	// Create status badge
	statusBadge := canvas.NewText("Offline", color.RGBA{R: 255, G: 0, B: 0, A: 255}) // Red color for offline
	statusBadge.Alignment = fyne.TextAlignCenter
	statusBadge.TextStyle = fyne.TextStyle{Bold: true}
	// Assuming you have an IsOnline field in DeviceInfo
	// if device.IsOnline {
	// 	statusBadge.Text = "Online"
	// 	statusBadge.Color = color.RGBA{R: 0, G: 255, B: 0, A: 255} // Green color for online
	// }

	// Create buttons for actions
	setVoiceButton := widget.NewButtonWithIcon("Set Voice", theme.VolumeUpIcon(), func() {
		err := setVoice(client, device.Did, 7, 4, `{"id":"VI","url":"https://awssgp0.fds.api.xiaomi.com/dreame-product/resources/934a776408f1391620c283de80596fbc","md5":"934a776408f1391620c283de80596fbc","size":2050200}`)
		if err != nil {
			log.Println("Failed to set voice property:", err)
			showError(fyne.CurrentApp().Driver().AllWindows()[0], "Failed to Set Voice", err.Error())
		} else {
			// Hiển thị thông báo thành công thay vì ghi log
			dialog.ShowInformation("Success", "Voice property set successfully", fyne.CurrentApp().Driver().AllWindows()[0])
		}
	})
	setFirmwareButton := widget.NewButtonWithIcon("Set Firmware", theme.DownloadIcon(), func() {
		log.Println("Set Firmware clicked for device:", device.Did)
	})
	setCountryButton := widget.NewButtonWithIcon("Set Country", theme.NavigateNextIcon(), func() {
		err := setCountry(client, device.Did, 99, 19, "CN")
		if err != nil {
			log.Println("Failed to set country property:", err)
			showError(fyne.CurrentApp().Driver().AllWindows()[0], "Failed to Set Country", err.Error())
		} else {
			// Hiển thị thông báo thành công thay vì ghi log
			dialog.ShowInformation("Success", "Country property set successfully", fyne.CurrentApp().Driver().AllWindows()[0])
		}
	})
	startCleanButton := widget.NewButtonWithIcon("Start Clean", theme.MediaPlayIcon(), func() {
		err := startClean(client, device.Did, 4, 1)
		if err != nil {
			log.Println("Failed to start cleaning:", err)
			showError(fyne.CurrentApp().Driver().AllWindows()[0], "Failed to Start Cleaning", err.Error())
		} else {
			// Hiển thị thông báo thành công thay vì ghi log
			dialog.ShowInformation("Success", "Cleaning started successfully", fyne.CurrentApp().Driver().AllWindows()[0])
		}
	})

	// Disable buttons if the device is offline
	// if !device.IsOnline {
	// 	setVoiceButton.Disable()
	// 	setFirmwareButton.Disable()
	// 	setCountryButton.Disable()
	// 	startCleanButton.Disable()
	// }

	// Create a card for the device
	card := widget.NewCard(
		device.Model,
		"",
		container.NewVBox(
			statusBadge,
			deviceIDLabel,
			modelLabel,
			localIPLabel,
			firmwareVersionLabel,
			container.NewHBox(
				layout.NewSpacer(),
				setVoiceButton,
				setFirmwareButton,
				setCountryButton,
				startCleanButton,
			),
		),
	)

	// Add border and padding to the card
	cardContainer := container.New(
		layout.NewBorderLayout(nil, nil, nil, nil),
		canvas.NewRectangle(color.RGBA{R: 220, G: 220, B: 220, A: 255}), // Light gray border
		container.NewVBox(
			layout.NewSpacer(),
			card,
			layout.NewSpacer(),
		),
	)

	return cardContainer
}

// Function to set voice property
func setVoice(client *cloud.Client, deviceID string, siid, piid int, value string) error {
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

// Function to set country property using rpcRequest
func setCountry(client *cloud.Client, deviceID string, siid, piid int, value string) error {
	params := map[string]any{
		"siid":  siid,
		"piid":  piid,
		"value": value,
	}

	result, err := cloud.Client.rpcRequest(context.Background(), deviceID, "set_country", params)
	if err != nil {
		return err
	}

	// Optionally, you can process the result here if needed
	fmt.Println("RPC Request Result:", string(result))

	return nil
}

// Function to start cleaning
func startClean(client *cloud.Client, deviceID string, siid, aiid int) error {
	action := types.DeviceAction{
		DID:  deviceID,
		SIID: siid,
		AIID: aiid,
	}

	if err := client.ExecuteDeviceAction(context.Background(), action); err != nil {
		return err
	}

	return nil
}

// Function to handle RPC requests

// Function to show error messages in a dialog
func showError(window fyne.Window, title, message string) {
	dialog.NewError(
		fmt.Errorf(message),
		window,
	).Show()
}
