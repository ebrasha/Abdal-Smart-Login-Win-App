//---------------------------------------------------------------------------

#ifndef Unit1H
#define Unit1H
//---------------------------------------------------------------------------
#include <System.Classes.hpp>
#include <Vcl.Controls.hpp>
#include <Vcl.StdCtrls.hpp>
#include <Vcl.Forms.hpp>
#include <Vcl.ExtCtrls.hpp>
#include <Vcl.Imaging.pngimage.hpp>
#include <Vcl.Buttons.hpp>
#include <Vcl.ComCtrls.hpp>
#include "ipwhttp.h"
#include "ipcaes.h"
#include "ipcrc4.h"
#include "ipchash.h"
//---------------------------------------------------------------------------
class TForm1 : public TForm
{
__published:	// IDE-managed Components
	TImage *MainIMG;
	TImage *SecIMG;
	TImage *NoSecIMG;
	TEdit *SecureKey;
	TProgressBar *ProgressBar;
	TipwHTTP *HTTP;
	TListBox *LogTracker;
	TTimer *Timer;
	TLabel *RevTimeLab;
	TImage *SecretKeyBT;
	TImage *LogTrackerBt;
	TImage *LockBt;
	TImage *SettingBT;
	TImage *WelComeIMG;
	TImage *EnterPassBt;
	TipcRC4 *abdalcryptor;
	TipcAES *abdaldecryptor;
	TipcHash *abdalhasher;
	void __fastcall HTTPEndTransfer(TObject *Sender, TipwHTTPEndTransferEventParams *e);
	void __fastcall HTTPHeader(TObject *Sender, TipwHTTPHeaderEventParams *e);
	void __fastcall HTTPStartTransfer(TObject *Sender, TipwHTTPStartTransferEventParams *e);
	void __fastcall HTTPTransfer(TObject *Sender, TipwHTTPTransferEventParams *e);
	void __fastcall FormClose(TObject *Sender, TCloseAction &Action);
	void __fastcall TimerTimer(TObject *Sender);
	void __fastcall SecretKeyBTClick(TObject *Sender);
	void __fastcall LogTrackerBtClick(TObject *Sender);
	void __fastcall LockBtClick(TObject *Sender);
	void __fastcall FormShow(TObject *Sender);
	void __fastcall EnterPassBtClick(TObject *Sender);
	void __fastcall SettingBTClick(TObject *Sender);
	void __fastcall SecureKeyKeyPress(TObject *Sender, System::WideChar &Key);


private:	// User declarations
public:		// User declarations
	__fastcall TForm1(TComponent* Owner);
};
//---------------------------------------------------------------------------
extern PACKAGE TForm1 *Form1;
//---------------------------------------------------------------------------
#endif
