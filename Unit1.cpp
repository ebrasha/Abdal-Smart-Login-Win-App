// ---------------------------------------------------------------------------

#include <vcl.h>
#pragma hdrstop

#include "Unit1.h"
// ---------------------------------------------------------------------------
#pragma package(smart_init)
#pragma link "ipwhttp"
#pragma link "ipcaes"
#pragma link "ipcrc4"
#pragma link "ipchash"
#include <Clipbrd.hpp>
#pragma resource "*.dfm"
TForm1 *Form1;

unsigned long LenTotal;
String tempFolder = GetEnvironmentVariable("USERPROFILE"); // Define Temp Folder
int TimeRev = 20; // For Reverse 20 Sec
String password = "abdal";

// ---------------------------------------------------------------------------
__fastcall TForm1::TForm1(TComponent* Owner) : TForm(Owner) {
}

// ---------------------------------------------------------------------------
void __fastcall TForm1::HTTPEndTransfer(TObject *Sender,
	TipwHTTPEndTransferEventParams *e)

{
	ProgressBar->Position = 0;
	SecIMG->Visible = true;
	NoSecIMG->Visible = false;
}
// ---------------------------------------------------------------------------

void __fastcall TForm1::HTTPHeader(TObject *Sender,
	TipwHTTPHeaderEventParams *e)

{

	LogTracker->Items->Add(" Header : " + e->Field + ":" + e->Value);

	if (e->Field.UpperCase() == "CONTENT-LENGTH") {

		LenTotal = e->Value.ToInt();

	}

}
// ---------------------------------------------------------------------------

void __fastcall TForm1::HTTPStartTransfer(TObject *Sender,
	TipwHTTPStartTransferEventParams *e)

{
	ProgressBar->Position = 0;
}
// ---------------------------------------------------------------------------

void __fastcall TForm1::HTTPTransfer(TObject *Sender,
	TipwHTTPTransferEventParams *e)

{
	LogTracker->Items->Strings[LogTracker->Items->Count - 1] =
		AnsiString((int)e->BytesTransferred) + AnsiString(" bytes written");
	ProgressBar->Position = (e->BytesTransferred * 100) / LenTotal;

}

// ---------------------------------------------------------------------------

void __fastcall TForm1::FormClose(TObject *Sender, TCloseAction &Action) {
	HTTP->Interrupt();
	// Start Remove Secret Key File
	if (FileExists(tempFolder + "\\jeyse89h.txt")) {
		DeleteFileW(tempFolder + "\\jeyse89h.txt");
	} // End Remove Secret Key File

}

// ---------------------------------------------------------------------------
void __fastcall TForm1::TimerTimer(TObject *Sender) {

	RevTimeLab->Caption = AnsiString(TimeRev = TimeRev - 1);
	ProgressBar->Position = RevTimeLab->Caption.ToInt();
	if (TimeRev == 0) {

		NoSecIMG->Visible = true;
		SecIMG->Visible = false;
		Clipboard()->AsText = ""; // Empty The ClipBoard
		// Start Remove Secret Key File
		if (FileExists(tempFolder + "\\jeyse89h.txt")) {
			DeleteFileW(tempFolder + "\\jeyse89h.txt");
		} // End Remove Secret Key File
		Timer->Enabled = false;

	}

}

// ---------------------------------------------------------------------------
void __fastcall TForm1::SecretKeyBTClick(TObject *Sender) {
	LogTracker->Visible = false;
	WelComeIMG->Visible = false;

	if (ProgressBar->Position != 0) {
		MessageDlg(L"You Can Not The Request code At This Moment", mtWarning,
			TMsgDlgButtons() << mbOK, 0);

	}
	else {
		DeleteFileW(tempFolder + "\\jeyse89h.txt");

		MainIMG->Visible = false;
		SecureKey->Visible = true;
		LogTracker->Visible = false;
		NoSecIMG->Visible = true;
		LenTotal = 0x7FFFFFFF;
		HTTP->FollowRedirects = frAlways;
		// Start Proc File From Server
		HTTP->LocalFile = tempFolder + "\\jeyse89h.txt";
		HTTP->Get("http://hackers.zone/keygsmartl.php");

		// Start Proc File From Server

		String SecretFileStr = tempFolder + L"\\jeyse89h.txt";
		TTextReader * SecretFileStrOpen = new TStreamReader(SecretFileStr);

		String SecretStr = SecretFileStrOpen->ReadLine();
		// int SecretStrFromServer = StrToInt(SecretStr);
		// Decrypt The Server Token    (AES)
		abdaldecryptor->UseHex = True;
		abdaldecryptor->InputMessage = SecretStr;
		abdaldecryptor->KeyPassword = "nkw5L8ayq=@UYxXc4YHqNq9LUgyTDLtwfEKEN";
		// From Server
		abdaldecryptor->Decrypt();
		String decryptSecretStrFromServer = abdaldecryptor->OutputMessage;

		// .Decrypt The Server Token

		// Crypt For Server (RC4)
		abdalcryptor->UseHex = True;
		abdalcryptor->InputMessage = decryptSecretStrFromServer;
		abdalcryptor->KeyPassword = "Pku78TPybuzCnGvRU@=y074Bawk6O5MR4nWSq";
		// From Smart Login

		abdalcryptor->Encrypt();

		SecretFileStrOpen->Close();

		// Start Proc File From Server

		// Hashing  Process
		abdalhasher->Reset();
		abdalhasher->Algorithm = 7; // MD5
		abdalhasher->EncodeHash = True;
		abdalhasher->Key = "8@yr=v16O5M3PPybuzC";
		abdalhasher->InputMessage = abdalcryptor->OutputMessage;
		abdalhasher->ComputeHash();
		// .  Hashing  Process

		// // Changing The Hash For Undetecting
		// UnicodeString abdalHash = abdalhasher->HashValue;
		// UnicodeString secureAbdalHash = "";
		// secureAbdalHash = StringReplace(abdalHash, 3, "",
		// TReplaceFlags(rfReplaceAll));
		// secureAbdalHash = StringReplace(abdalHash, 4, "",
		// TReplaceFlags(rfReplaceAll));
		// secureAbdalHash = StringReplace(abdalHash, 5, "",
		// TReplaceFlags(rfReplaceAll));
		// // . Changing The Hash For Undetecting

		SecureKey->Text = abdalhasher->HashValue; ;
		Clipboard()->AsText = abdalhasher->HashValue; // Copy To ClipBoard

		// Start Reverse Time For ProgressBar
		RevTimeLab->Visible = true;
		Timer->Interval = 1000;
		Timer->Enabled = true;
		TimeRev = 20;
		RevTimeLab->Caption = AnsiString(TimeRev);
		ProgressBar->Min = 0;
		ProgressBar->Max = 20;
		ProgressBar->Position = 20;

		// End Reverse Time For ProgressBar

	}
}
// ---------------------------------------------------------------------------

void __fastcall TForm1::LogTrackerBtClick(TObject *Sender) {
	LogTracker->Visible = true;
}

// ---------------------------------------------------------------------------
void __fastcall TForm1::LockBtClick(TObject *Sender) {
	SecureKey->Text = "";
	RevTimeLab->Visible = false;
	Timer->Enabled = false;
	ProgressBar->Position = 0;
	MainIMG->Visible = true;
	WelComeIMG->Visible = false;
	SecIMG->Visible = false;
	NoSecIMG->Visible = false;
	SecureKey->Visible = true;
	LogTrackerBt->Visible = false;
	SettingBT->Visible = false;
	SecretKeyBT->Visible = false;
	EnterPassBt->Visible = true;

}
// ---------------------------------------------------------------------------

void __fastcall TForm1::FormShow(TObject *Sender) {

	MainIMG->Visible = true;
	WelComeIMG->Visible = false;
	SecIMG->Visible = false;
	NoSecIMG->Visible = false;
	SecureKey->Visible = true;
	LogTrackerBt->Visible = false;
	SettingBT->Visible = false;
	SecretKeyBT->Visible = false;
	EnterPassBt->Visible = true;
	SecureKey->Focused();

}

// ---------------------------------------------------------------------------
void __fastcall TForm1::EnterPassBtClick(TObject *Sender) {
	if (SecureKey->Text == password) {

		SecureKey->Visible = false;
		SecureKey->Text = "";
		EnterPassBt->Visible = false;
		MainIMG->Visible = false;
		WelComeIMG->Visible = true;
		LogTrackerBt->Visible = true;
		SettingBT->Visible = true;
		SecretKeyBT->Visible = true;

	}
	else {
		MessageDlg(L"Password Is Wrong !", mtWarning,
			TMsgDlgButtons() << mbOK, 0);
	}
}

// ---------------------------------------------------------------------------
void __fastcall TForm1::SettingBTClick(TObject *Sender) {
	MessageDlg(L"Hi Dear Mohsen ! Setting Is Not Available On This Version",
		mtWarning, TMsgDlgButtons() << mbOK, 0);
}
// ---------------------------------------------------------------------------

void __fastcall TForm1::SecureKeyKeyPress(TObject *Sender,
	System::WideChar &Key)

{
	if (SecureKey->Text == password) {

		SecureKey->Visible = false;
		SecureKey->Text = "";
		EnterPassBt->Visible = false;
		MainIMG->Visible = false;
		WelComeIMG->Visible = true;
		LogTrackerBt->Visible = true;
		SettingBT->Visible = true;
		SecretKeyBT->Visible = true;

	}
}
// ---------------------------------------------------------------------------
