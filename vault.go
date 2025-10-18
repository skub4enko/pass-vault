package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

type Entry struct {
	Site     string `json:"site"`
	Account  string `json:"account"`
	Password string `json:"password"`
}

type Vault struct {
	Entries []Entry `json:"entries"`
}

var dbFile = "vault.db"
var masterPassword string
var vault Vault

// -------------------- Encryption --------------------
func encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

// -------------------- Vault I/O --------------------
func loadVault() error {
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		vault = Vault{}
		return saveVault()
	}
	data, err := os.ReadFile(dbFile)
	if err != nil {
		return err
	}
	plain, err := decrypt(data, []byte(masterPassword))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, &vault)
}

func saveVault() error {
	data, err := json.Marshal(vault)
	if err != nil {
		return err
	}
	ciphertext, err := encrypt(data, []byte(masterPassword))
	if err != nil {
		return err
	}
	return os.WriteFile(dbFile, ciphertext, 0600)
}

// -------------------- GUI --------------------
func main() {
	a := app.New()
	w := a.NewWindow("PassVault")
	w.Resize(fyne.NewSize(700, 400))

	masterEntry := widget.NewPasswordEntry()
	masterEntry.SetPlaceHolder("Enter master password")

loginBtn := widget.NewButton("Unlock / Create", func() {
	masterPassword = masterEntry.Text
	if _, err := os.Stat(dbFile); os.IsNotExist(err) {
		// Если файла нет — создаём новый vault
		vault = Vault{}
		if err := saveVault(); err != nil {
			dialog.ShowError(err, w)
			return
		}
	} else {
		// Если файл есть — загружаем существующий
		if err := loadVault(); err != nil {
			dialog.ShowError(err, w)
			return
		}
	}
	w.SetContent(vaultUI(w))
})

	w.SetContent(container.NewVBox(
		widget.NewLabel("Master Password:"),
		masterEntry,
		loginBtn,
	))
	w.ShowAndRun()
}

func vaultUI(w fyne.Window) fyne.CanvasObject {
	siteFilter := widget.NewEntry()
	siteFilter.SetPlaceHolder("Search site...")

	siteSelect := widget.NewSelect([]string{}, nil)
	accountSelect := widget.NewSelect([]string{}, nil)

	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetText("") // изначально пусто
	passwordEntry.Disable()   // нельзя редактировать

	showBtn := widget.NewButton("Show Password", nil)
	copyBtn := widget.NewButton("Copy Password", nil)

	refreshSelects := func() {
		filter := strings.ToLower(siteFilter.Text)
		sites := uniqueSites()
		filteredSites := []string{}
		for _, s := range sites {
			if strings.Contains(strings.ToLower(s), filter) {
				filteredSites = append(filteredSites, s)
			}
		}
		siteSelect.Options = filteredSites
		siteSelect.Refresh()

		accounts := entriesForSite(siteSelect.Selected)
		accountSelect.Options = accounts
		accountSelect.Refresh()

		if len(accounts) > 0 {
			accountSelect.SetSelected(accounts[0])
			passwordEntry.SetText("********")
		} else {
			passwordEntry.SetText("")
		}
	}

	siteFilter.OnChanged = func(s string) {
		refreshSelects()
	}

	siteSelect.OnChanged = func(s string) {
		accounts := entriesForSite(s)
		accountSelect.Options = accounts
		accountSelect.Refresh()
		if len(accounts) > 0 {
			accountSelect.SetSelected(accounts[0])
			passwordEntry.SetText("********")
		} else {
			passwordEntry.SetText("")
		}
	}

	accountSelect.OnChanged = func(a string) {
		if a != "" {
			passwordEntry.SetText("********")
		} else {
			passwordEntry.SetText("")
		}
	}

	showBtn.OnTapped = func() {
		pwd := getPassword(siteSelect.Selected, accountSelect.Selected)
		if pwd != "" {
			passwordEntry.SetText(pwd)
			// скрыть через 3 секунды
			go func() {
				time.Sleep(3 * time.Second)
				passwordEntry.SetText("********")
			}()
		}
	}

	copyBtn.OnTapped = func() {
		if w.Clipboard() != nil {
			w.Clipboard().SetContent(getPassword(siteSelect.Selected, accountSelect.Selected))
		}
	}

	addBtn := widget.NewButton("Add Entry", func() {
		siteEntry := widget.NewEntry()
		siteEntry.SetPlaceHolder("Site")
		accountEntry := widget.NewEntry()
		accountEntry.SetPlaceHolder("Account")
		passEntry := widget.NewPasswordEntry()
		passEntry.SetPlaceHolder("Password")

		form := &widget.Form{
			Items: []*widget.FormItem{
				{Text: "Site", Widget: siteEntry},
				{Text: "Account", Widget: accountEntry},
				{Text: "Password", Widget: passEntry},
			},
			OnSubmit: func() {
				vault.Entries = append(vault.Entries, Entry{
					Site:     siteEntry.Text,
					Account:  accountEntry.Text,
					Password: passEntry.Text,
				})
				saveVault()
				refreshSelects()
			},
		}
		dialog.ShowCustom("Add Entry", "Cancel", form, w)
	})

	importBtn := widget.NewButton("Import CSV/JSON", func() {
		fd := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
			if err != nil || r == nil {
				return
			}
			defer r.Close()
			path := r.URI().Path()
			if strings.HasSuffix(path, ".csv") {
				importCSV(path)
			} else if strings.HasSuffix(path, ".json") {
				importJSON(path)
			} else {
				dialog.ShowInformation("Error", "Unsupported file type", w)
			}
			refreshSelects()
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".csv", ".json"}))
		fd.Show()
	})

	exportBtn := widget.NewButton("Export CSV/JSON", func() {
		fd := dialog.NewFileSave(func(r fyne.URIWriteCloser, err error) {
			if err != nil || r == nil {
				return
			}
			defer r.Close()
			path := r.URI().Path()
			if strings.HasSuffix(path, ".csv") {
				exportCSV(path)
			} else if strings.HasSuffix(path, ".json") {
				exportJSON(path)
			} else {
				dialog.ShowInformation("Error", "Unsupported file type", w)
			}
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".csv", ".json"}))
		fd.Show()
	})

	refreshSelects()

	topBar := container.NewHBox(siteFilter, addBtn, importBtn, exportBtn)
	selectBar := container.NewHBox(siteSelect, accountSelect)
	passBar := container.NewHBox(passwordEntry, showBtn, copyBtn)

	return container.NewVBox(topBar, selectBar, passBar)
}

// -------------------- Helpers --------------------
func uniqueSites() []string {
	m := make(map[string]struct{})
	for _, e := range vault.Entries {
		m[e.Site] = struct{}{}
	}
	sites := []string{}
	for s := range m {
		sites = append(sites, s)
	}
	return sites
}

func entriesForSite(site string) []string {
	accounts := []string{}
	for _, e := range vault.Entries {
		if e.Site == site {
			accounts = append(accounts, e.Account)
		}
	}
	return accounts
}

func getPassword(site, account string) string {
	for _, e := range vault.Entries {
		if e.Site == site && e.Account == account {
			return e.Password
		}
	}
	return ""
}

// -------------------- CSV/JSON --------------------
func importCSV(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	r := csv.NewReader(f)
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if len(record) < 3 {
			continue
		}
		vault.Entries = append(vault.Entries, Entry{
			Site:     record[0],
			Account:  record[1],
			Password: record[2],
		})
	}
	return saveVault()
}

func importJSON(file string) error {
	f, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	var entries []Entry
	if err := json.Unmarshal(f, &entries); err != nil {
		return err
	}
	vault.Entries = append(vault.Entries, entries...)
	return saveVault()
}

func exportCSV(file string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	for _, e := range vault.Entries {
		w.Write([]string{e.Site, e.Account, e.Password})
	}
	return nil
}

func exportJSON(file string) error {
	data, err := json.Marshal(vault.Entries)
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0600)
}
