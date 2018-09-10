/********************************************************************************
** Form generated from reading UI file 'rpcconsole.ui'
**
** Created by: Qt User Interface Compiler version 5.5.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_RPCCONSOLE_H
#define UI_RPCCONSOLE_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QFrame>
#include <QtWidgets/QGridLayout>
#include <QtWidgets/QGroupBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSlider>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QTableView>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>
#include "trafficgraphwidget.h"

QT_BEGIN_NAMESPACE

class Ui_RPCConsole
{
public:
    QVBoxLayout *verticalLayout_2;
    QTabWidget *tabWidget;
    QWidget *tab_info;
    QGridLayout *gridLayout;
    QLabel *label_9;
    QLabel *label_5;
    QLabel *clientName;
    QLabel *label_6;
    QLabel *clientVersion;
    QLabel *label_14;
    QLabel *openSSLVersion;
    QLabel *label_berkeleyDBVersion;
    QLabel *berkeleyDBVersion;
    QLabel *label_12;
    QLabel *buildDate;
    QLabel *label_13;
    QLabel *startupTime;
    QLabel *label_11;
    QLabel *label_8;
    QLabel *networkName;
    QLabel *label_7;
    QLabel *numberOfConnections;
    QLabel *label_10;
    QLabel *label_3;
    QLabel *numberOfBlocks;
    QLabel *label_2;
    QLabel *lastBlockTime;
    QSpacerItem *verticalSpacer_2;
    QLabel *labelDebugLogfile;
    QPushButton *openDebugLogfileButton;
    QSpacerItem *verticalSpacer;
    QWidget *tab_console;
    QVBoxLayout *verticalLayout_3;
    QTextEdit *messagesWidget;
    QHBoxLayout *horizontalLayout;
    QLabel *label;
    QLineEdit *lineEdit;
    QPushButton *clearButton;
    QWidget *tab_nettraffic;
    QHBoxLayout *horizontalLayout_3;
    QVBoxLayout *verticalLayout_4;
    TrafficGraphWidget *trafficGraph;
    QHBoxLayout *horizontalLayout_2;
    QSlider *sldGraphRange;
    QLabel *lblGraphRange;
    QPushButton *btnClearTrafficGraph;
    QVBoxLayout *verticalLayout;
    QGroupBox *groupBox;
    QVBoxLayout *verticalLayout_5;
    QHBoxLayout *horizontalLayout_4;
    QFrame *line;
    QLabel *label_16;
    QLabel *lblBytesIn;
    QHBoxLayout *horizontalLayout_5;
    QFrame *line_2;
    QLabel *label_17;
    QLabel *lblBytesOut;
    QSpacerItem *verticalSpacer_4;
    QWidget *tab_peers;
    QGridLayout *gridLayout_2;
    QTableView *peerWidget;
    QLabel *peerHeading;
    QWidget *detailWidget;
    QGridLayout *gridLayout_3;
    QLabel *label_23;
    QLabel *peerDirection;
    QLabel *label_21;
    QLabel *peerVersion;
    QLabel *label_28;
    QLabel *peerSubversion;
    QLabel *label_4;
    QLabel *peerServices;
    QLabel *label_29;
    QLabel *peerHeight;
    QLabel *label_27;
    QLabel *peerSyncHeight;
    QLabel *label_24;
    QLabel *peerBanScore;
    QLabel *label_22;
    QLabel *peerConnTime;
    QLabel *label_15;
    QLabel *peerLastSend;
    QLabel *label_19;
    QLabel *peerLastRecv;
    QLabel *label_18;
    QLabel *peerBytesSent;
    QLabel *label_20;
    QLabel *peerBytesRecv;
    QLabel *label_26;
    QLabel *peerPingTime;
    QLabel *label_timeoffset;
    QLabel *timeoffset;
    QSpacerItem *verticalSpacer_3;

    void setupUi(QWidget *RPCConsole)
    {
        if (RPCConsole->objectName().isEmpty())
            RPCConsole->setObjectName(QStringLiteral("RPCConsole"));
        RPCConsole->resize(740, 450);
        RPCConsole->setStyleSheet(QLatin1String("\n"
"QStatusBar {\n"
"background-color:#ffffff;\n"
"}\n"
"\n"
".QFrame {\n"
"background-color:transparent;\n"
"border:0px solid #fff;\n"
"}\n"
"\n"
"QMenuBar {\n"
"background-color:#fff;\n"
"}\n"
"\n"
"QMenuBar::item {\n"
"background-color:#fff;\n"
"}\n"
"\n"
"QMenuBar::item:selected {\n"
"background-color:#f8f6f6;\n"
"}\n"
"\n"
"QMenu {\n"
"background-color:#f8f6f6;\n"
"}\n"
"\n"
"QMenu::item {\n"
"color:#333;\n"
"}\n"
"\n"
"QMenu::item:selected {\n"
"background-color:#f2f0f0;\n"
"color:#333;\n"
"}\n"
"\n"
"QToolBar {\n"
"background-color:#fff;\n"
"border:0px solid #000;\n"
"padding:0;\n"
"margin:0;\n"
"}\n"
"\n"
"QToolBar > QToolButton {\n"
"background-color:#fff;\n"
"border:0px solid #333;\n"
"min-height:2.5em;\n"
"min-width: 8em;\n"
"padding: 0em 1em;\n"
"/*font-weight:bold;*/\n"
"color:#333;\n"
"}\n"
"\n"
"QToolBar > QToolButton:checked {\n"
"background-color:#183862;\n"
"color:#fff;\n"
"font-weight:bold;\n"
"}\n"
"\n"
"QMessageBox {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"/**************************"
                        "*****************************/\n"
"\n"
"QLabel { /* Base Text Size & Color */\n"
"font-size:12px;\n"
"color:#333333;\n"
"}\n"
"\n"
".QCheckBox { /* Checkbox Labels */\n"
"color:#333333;\n"
"background-color:transparent;\n"
"}\n"
"\n"
".QCheckBox:hover {\n"
"background-color:transparent;\n"
"}\n"
"\n"
".QValidatedLineEdit, .QLineEdit { /* Text Entry Fields */\n"
"border: 1px solid #82C3E6;\n"
"font-size:11px;\n"
"min-height:25px;\n"
"outline:0;\n"
"padding:3px;\n"
"background-color:#fcfcfc;\n"
"}\n"
"\n"
".QLineEdit:!focus {\n"
"font-size:12px;\n"
"}\n"
"\n"
".QValidatedLineEdit:disabled, .QLineEdit:disabled {\n"
"background-color:#f2f2f2;\n"
"}\n"
"\n"
"/*******************************************************/\n"
"\n"
"QPushButton { /* Global Button Style */\n"
"\n"
"background-color:#183862;\n"
"\n"
"border:1;\n"
"\n"
"border-radius:3px;\n"
"\n"
"color:#ffffff;\n"
"\n"
"font-size:12px;\n"
"\n"
"font-weight:bold;\n"
"\n"
"height: 26px;\n"
"\n"
"padding-left:25px;\n"
"\n"
"padding-right:25px;\n"
"\n"
"padding-t"
                        "op:5px;\n"
"\n"
"padding-bottom:5px;\n"
"\n"
"margin-right: 10px;\n"
"\n"
"}\n"
"\n"
"\n"
"\n"
"QPushButton:hover { /* Global Button Style hover */\n"
"\n"
"background-color:#f57026;\n"
"\n"
"border:1;\n"
"\n"
"border-radius:3px;\n"
"\n"
"color:#ffffff;\n"
"\n"
"font-size:12px;\n"
"\n"
"font-weight:bold;\n"
"\n"
"height: 26px;\n"
"\n"
"padding-left:25px;\n"
"\n"
"padding-right:25px;\n"
"\n"
"padding-top:5px;\n"
"\n"
"padding-bottom:5px;\n"
"\n"
"margin-right: 10px;\n"
"\n"
"}\n"
"\n"
"QPushButton:focus {\n"
"border:none;\n"
"outline:none;\n"
"}\n"
"\n"
"QPushButton:pressed {\n"
"border:1px solid #333;\n"
"}\n"
"\n"
"QComboBox { /* Dropdown Menus */\n"
"border:1px solid #82C3E6;\n"
"padding: 3px 5px 3px 5px;\n"
"background:#fcfcfc;\n"
"min-height:25px;\n"
"color:#818181;\n"
"}\n"
"\n"
"QComboBox:checked {\n"
"background:#f2f2f2;\n"
"}\n"
"\n"
"QComboBox:editable {\n"
"background: #183862;\n"
"color:#616161;\n"
"border:0px solid transparent;\n"
"}\n"
"\n"
"QComboBox::drop-down {\n"
"width:25px;\n"
"border:0px;\n"
""
                        "}\n"
"\n"
"QComboBox::down-arrow {\n"
"border-image: url(':/images/light/drkblue_downArrow') 0 0 0 0 stretch stretch;\n"
"}\n"
"\n"
"QComboBox QListView {\n"
"background:#fff;\n"
"border:1px solid #333;\n"
"padding-right:1px;\n"
"padding-left:1px;\n"
"}\n"
"\n"
"QComboBox QAbstractItemView::item { margin:4px; }\n"
"\n"
"QComboBox::item {\n"
"color:#818181;\n"
"}\n"
"\n"
"QComboBox::item:alternate {\n"
"background:#fff;\n"
"}\n"
"\n"
"QComboBox::item:selected {\n"
"border:0px solid transparent;\n"
"background:#f2f2f2;\n"
"}\n"
"\n"
"QComboBox::indicator {\n"
"background-color:transparent;\n"
"selection-background-color:transparent;\n"
"color:transparent;\n"
"selection-color:transparent;\n"
"}\n"
"\n"
"QAbstractSpinBox {\n"
"border:1px solid #82C3E6;\n"
"padding: 3px 5px 3px 5px;\n"
"background:#fcfcfc;\n"
"min-height:25px;\n"
"color:#818181;\n"
"}\n"
"\n"
"QAbstractSpinBox::up-button {\n"
"subcontrol-origin: border;\n"
"subcontrol-position: top right;\n"
"width:21px;\n"
"background:#fcfcfc;\n"
"border-left:0px;"
                        "\n"
"border-right:1px solid #82C3E6;\n"
"border-top:1px solid #82C3E6;\n"
"border-bottom:0px;\n"
"padding-right:1px;\n"
"padding-left:5px;\n"
"padding-top:2px;\n"
"}\n"
"\n"
"QAbstractSpinBox::up-arrow {\n"
"image:url(':/images/light/drkblue_upArrow_small');\n"
"}\n"
"\n"
"QAbstractSpinBox::down-button {\n"
"subcontrol-origin: border;\n"
"subcontrol-position: bottom right;\n"
"width:21px;\n"
"background:#fcfcfc;\n"
"border-top:0px;\n"
"border-left:0px;\n"
"border-right:1px solid #82C3E6;\n"
"border-bottom:1px solid #82C3E6;\n"
"padding-right:1px;\n"
"padding-left:5px;\n"
"padding-bottom:2px;\n"
"}\n"
"\n"
"QAbstractSpinBox::down-arrow {\n"
"image:url(':/images/light/drkblue_downArrow_small');\n"
"}\n"
"\n"
"QCheckBox {\n"
"spacing: 5px;\n"
"}\n"
"\n"
"QCheckBox::indicator {\n"
"width: 16px;\n"
"height: 16px;\n"
"}\n"
"\n"
"\n"
"\n"
"/*******************************************************/\n"
"\n"
"QHeaderView { /* Table Header */\n"
"background-color:transparent;\n"
"}\n"
"\n"
"QHeaderView::section { /* Table"
                        " Header Sections */\n"
"qproperty-alignment:center;\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 0.25, stop: 0 #1070B0, stop: 1 #183862);\n"
"color:#fff;\n"
"min-height:25px;\n"
"font-weight:bold;\n"
"font-size:14px;\n"
"outline:0;\n"
"border:0px solid #fff;\n"
"border-right:1px solid #fff;\n"
"padding-left:5px;\n"
"padding-right:5px;\n"
"padding-top:2px;\n"
"padding-bottom:2px;\n"
"}\n"
"\n"
"QHeaderView::section:last {\n"
"border-right: 0px solid #d7d7d7;\n"
"}\n"
"\n"
".QScrollArea {\n"
"background:transparent;\n"
"border:0px;\n"
"}\n"
"\n"
".QTableView { /* Table - has to be selected as a class otherwise it throws off QCalendarWidget */\n"
"background:transparent;\n"
"border:0px solid #fff;\n"
"}\n"
"\n"
"QTableView::item { /* Table Item */\n"
"background-color:#fcfcfc;\n"
"font-size:12px;\n"
"}\n"
"\n"
"QTableView::item:selected { /* Table Item Selected */\n"
"background-color:#f0f0f0;\n"
"color:#333;\n"
"}\n"
"\n"
"QScrollBar { /* Scroll Bar */\n"
"\n"
"}\n"
"\n"
"QScrollBar:vertical { /"
                        "* Vertical Scroll Bar Attributes */\n"
"border:0;\n"
"background:#ffffff;\n"
"width:18px;\n"
"margin: 18px 0px 18px 0px;\n"
"}\n"
"\n"
"QScrollBar:horizontal { /* Horizontal Scroll Bar Attributes */\n"
"border:0;\n"
"background:#ffffff;\n"
"height:18px;\n"
"margin: 0px 18px 0px 18px;\n"
"}\n"
"\n"
"\n"
"QScrollBar::handle:vertical { /* Scroll Bar Slider - vertical */\n"
"background:#e0e0e0;\n"
"min-height:10px;\n"
"}\n"
"\n"
"QScrollBar::handle:horizontal { /* Scroll Bar Slider - horizontal */\n"
"background:#e0e0e0;\n"
"min-width:10px;\n"
"}\n"
"\n"
"QScrollBar::add-page, QScrollBar::sub-page { /* Scroll Bar Background */\n"
"background:#F8F6F6;\n"
"}\n"
"\n"
"QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical, QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { /* Define Arrow Button Dimensions */\n"
"background-color:#F8F6F6;\n"
"border: 1px solid #f2f0f0;\n"
"width:16px;\n"
"height:16px;\n"
"}\n"
"\n"
"QScrollBar::add-line:vertical:pressed, QScrollBar::sub-line:vertical:pressed, QS"
                        "crollBar::add-line:horizontal:pressed, QScrollBar::sub-line:horizontal:pressed {\n"
"background-color:#e0e0e0;\n"
"}\n"
"\n"
"QScrollBar::sub-line:vertical { /* Vertical - top button position */\n"
"subcontrol-position:top;\n"
"subcontrol-origin: margin;\n"
"}\n"
"\n"
"QScrollBar::add-line:vertical { /* Vertical - bottom button position */\n"
"subcontrol-position:bottom;\n"
"subcontrol-origin: margin;\n"
"}\n"
"\n"
"QScrollBar::sub-line:horizontal { /* Vertical - left button position */\n"
"subcontrol-position:left;\n"
"subcontrol-origin: margin;\n"
"}\n"
"\n"
"QScrollBar::add-line:horizontal { /* Vertical - right button position */\n"
"subcontrol-position:right;\n"
"subcontrol-origin: margin;\n"
"}\n"
"\n"
"QScrollBar:up-arrow, QScrollBar:down-arrow, QScrollBar:left-arrow, QScrollBar:right-arrow { /* Arrows Icon */\n"
"width:10px;\n"
"height:10px;\n"
"}\n"
"\n"
"QScrollBar:up-arrow {\n"
"background-image: url(':/images/light/drkblue_upArrow_small');\n"
"}\n"
"\n"
"QScrollBar:down-arrow {\n"
"background-image:"
                        " url(':/images/light/drkblue_downArrow_small');\n"
"}\n"
"\n"
"QScrollBar:left-arrow {\n"
"background-image: url(':/images/light/drkblue_leftArrow_small');\n"
"}\n"
"\n"
"QScrollBar:right-arrow {\n"
"background-image: url(':/images/light/drkblue_rightArrow_small');\n"
"}\n"
"\n"
"\n"
"/*******************************************************/\n"
"\n"
"/* DIALOG BOXES */\n"
"\n"
"QDialog .QTabWidget {\n"
"border-bottom:1px solid #333;\n"
"}\n"
"\n"
"QDialog .QTabWidget::pane {\n"
"border: 1px solid #d7d7d7;\n"
"}\n"
"\n"
"QDialog .QTabWidget QTabBar::tab {\n"
"background-color:#f2f0f0;\n"
"color:#333;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"padding-top:5px;\n"
"padding-bottom:5px;\n"
"border-top: 1px solid #d7d7d7;\n"
"}\n"
"\n"
"QDialog .QTabWidget QTabBar::tab:first {\n"
"border-left: 1px solid #d7d7d7;\n"
"}\n"
"\n"
"QDialog .QTabWidget QTabBar::tab:last {\n"
"border-right: 1px solid #d7d7d7;\n"
"}\n"
"\n"
"QDialog .QTabWidget QTabBar::tab:selected, QDialog .QTabWidget QTabBar::tab:hover {\n"
"back"
                        "ground-color:#ffffff;\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog .QTabWidget .QWidget {\n"
"background-color:#fff;\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog .QTabWidget .QWidget QAbstractSpinBox {\n"
"min-height:15px;\n"
"}\n"
"\n"
"QDialog .QTabWidget .QWidget QAbstractSpinBox::down-button {\n"
"width:15px;\n"
"}\n"
"\n"
"QDialog .QTabWidget .QWidget QAbstractSpinBox::up-button {\n"
"width:15px;\n"
"}\n"
"\n"
"QDialog .QTabWidget .QWidget QComboBox {\n"
"min-height:15px;\n"
"}\n"
"\n"
"QDialog QWidget { /* Remove Annoying Focus Rectangle */\n"
"outline: 0;\n"
"}\n"
"\n"
"/*******************************************************/\n"
"/* FILE MENU */\n"
"\n"
"/* Dialog: Open URI */\n"
"QDialog#OpenURIDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#OpenURIDialog QLabel#label { /* URI Label */\n"
"font-weight:bold;\n"
"}\n"
"\n"
"QDialog#OpenURIDialog QPushButton#selectFileButton { /* ... Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 25"
                        "0, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#OpenURIDialog QPushButton#selectFileButton:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#OpenURIDialog QPushButton#selectFileButton:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"/* Dialog: Sign / Verify Message */\n"
"QDialog#SignVerifyMessageDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#addressBookButton_SM { /* Address Book Button */\n"
"background-color:transparent;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPlainTextEdit { /* Message Signing Text */\n"
"border:1px solid #82C3E6;\n"
"background-color:#fff;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageD"
                        "ialog QPushButton#pasteButton_SM { /* Paste Button */\n"
"/* qproperty-icon: url(\":/icons/light/drkblue_editpaste\"); */\n"
"background-color:transparent;\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QLineEdit:!focus { /* Font Hack */\n"
"font-size:10px;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#copySignatureButton_SM { /* Copy Button */\n"
"/* qproperty-icon: url(\":/icons/light/drkblue_editcopy\"); */\n"
"background-color:transparent;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#clearButton_SM { /* Clear Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#clearButton_SM:hover {\n"
"background-color:qlineargradient(x1: 0, y1: "
                        "0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#clearButton_SM:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#addressBookButton_VM { /* Verify Message - Address Book Button */\n"
"background-color:transparent;\n"
"border:0;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#clearButton_VM { /* Verify Message - Clear Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#clearButton_VM:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, sto"
                        "p: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#SignVerifyMessageDialog QPushButton#clearButton_VM:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"/* Dialog: Send and Receive */\n"
"QWidget#AddressBookPage {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#newAddress { /* New Address Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#newAddress:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#newAddress:pressed {\n"
"border:1px"
                        " solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#copyAddress { /* Copy Address Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#copyAddress:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#copyAddress:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#deleteAddress { /* Delete Address Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px sol"
                        "id #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#deleteAddress:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QPushButton#deleteAddress:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QTableView { /* Address Listing */\n"
"font-size:12px;\n"
"}\n"
"\n"
"QWidget#AddressBookPage QHeaderView::section { /* Min width for Windows fix */\n"
"min-width:260px;\n"
"}\n"
"\n"
"/* SETTINGS MENU */\n"
"\n"
"/* Encrypt Wallet and Change Passphrase Dialog */\n"
"QDialog#AskPassphraseDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#AskPassphraseDialog QLabel#passLabel1, QDialog#AskPassphraseDialog QLabel#passLabel2, QDialog#AskPassphraseDialog QLabel#passLabel3 {\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
""
                        "min-width:170px;\n"
"min-height:33px; /* base width of 25px for QLineEdit, plus padding and border */\n"
"}\n"
"\n"
"/* Options Dialog */\n"
"QDialog#OptionsDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#OptionsDialog QValueComboBox, QDialog#OptionsDialog QSpinBox {\n"
"margin-top:5px;\n"
"margin-bottom:5px;\n"
"}\n"
"\n"
"QDialog#OptionsDialog QValidatedLineEdit, QDialog#OptionsDialog QValidatedLineEdit:disabled, QDialog#OptionsDialog QLineEdit, QDialog#OptionsDialog QLineEdit:disabled {\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"min-height:20px;\n"
"margin-top:0px;\n"
"margin-bottom:0px;\n"
"padding-top:1px;\n"
"padding-bottom:1px;\n"
"}\n"
"\n"
"QDialog#OptionsDialog > QLabel {\n"
"qproperty-alignment: 'AlignVCenter';\n"
"min-height:20px;\n"
"}\n"
"\n"
"QDialog#OptionsDialog QWidget#tabDisplay QValueComboBox {\n"
"margin-top:0px;\n"
"margin-bottom:0px;\n"
"}\n"
"\n"
"QDialog#OptionsDialog QLabel#label_3 { /* Translations Missing? Label */\n"
"qproperty-alignment: 'AlignVCenter |"
                        " AlignCenter';\n"
"color:#818181;\n"
"padding-bottom:8px;\n"
"}\n"
"\n"
"QDialog#OptionsDialog QCheckBox {\n"
"min-height:20px;\n"
"}\n"
"\n"
"QDialog#OptionsDialog QCheckBox#displayAddresses {\n"
"min-height:33px;\n"
"\n"
"}\n"
"\n"
"/* TOOLS MENU */\n"
"\n"
"QDialog#RPCConsole { /* RPC Console Dialog Box */\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#RPCConsole QWidget#tab_info QLabel#label_11, QDialog#RPCConsole QWidget#tab_info QLabel#label_10 { /* Margin between Network and Block Chain headers */\n"
"qproperty-alignment: 'AlignBottom';\n"
"min-height:25px;\n"
"min-width:180px;\n"
"}\n"
"\n"
"QDialog#RPCConsole QWidget#tab_peers  QLabel#peerHeading { /* Peers Info Header */\n"
"color:#183862;\n"
"}\n"
"\n"
"QDialog#RPCConsole QPushButton#openDebugLogfileButton {\n"
"max-width:60px;\n"
"}\n"
"\n"
"QDialog#RPCConsole QTextEdit#messagesWidget { /* Console Messages Window */\n"
"border:0;\n"
"}\n"
"\n"
"QDialog#RPCConsole QLineEdit#lineEdit { /* Console Input */\n"
"margin-right:5px;\n"
"}\n"
"\n"
"QD"
                        "ialog#RPCConsole QPushButton#clearButton { /* Console Clear Button */\n"
"background-color:transparent;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#RPCConsole .QGroupBox #line { /* Network In Line */\n"
"background-color:#00ff00;\n"
"}\n"
"\n"
"QDialog#RPCConsole .QGroupBox #line_2 { /* Network Out Line */\n"
"background:#ff0000;\n"
"}\n"
"\n"
"/* HELP MENU */\n"
"\n"
"/* Command Line Options Dialog */\n"
"QDialog#HelpMessageDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#HelpMessageDialog QScrollArea * {\n"
"background-color:#ffffff;\n"
"}\n"
"\n"
"QDialog#HelpMessageDialog QScrollBar:vertical, QDialog#HelpMessageDialog QScrollBar:horizontal {\n"
"border:0;\n"
"}\n"
"\n"
"/* About Proton Dialog */\n"
"QDialog#AboutDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#AboutDialog QLabel#label, QDialog#AboutDialog QLabel#copyrightLabel, QDialog#AboutDialog QLabel#label_2 { /* About Proton Contents */\n"
"margin-left:10px;\n"
"}\n"
"\n"
"QDialog#AboutDialog QLabel#"
                        "label_2 { /* Margin for About Proton text */\n"
"margin-right:10px;\n"
"}\n"
"\n"
"/* Edit Address Dialog */\n"
"QDialog#EditAddressDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#EditAddressDialog QLabel {\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-height:27px;\n"
"font-weight:normal;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"/* OVERVIEW SCREEN */\n"
"\n"
"QWidget .QFrame#frame { /* Wallet Balance */\n"
"min-width:490px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame > .QLabel {\n"
"min-width:190px;\n"
"font-weight:normal;\n"
"min-height:30px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#label_5 { /* Wallet Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"background-color:transparent;\n"
"color:#f4f4f5;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelWalletStatus { /* Wallet Sync Status */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"margin-left:3px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel"
                        "#labelSpendable { /* Spendable Header */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:12px;\n"
"margin-left:18px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelWatchonly { /* Watch-only Header */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:12px;\n"
"margin-left:16px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelBalanceText { /* Available Balance Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"background-color:#183862;\n"
"color:#ffffff;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"font-size:14px;\n"
"font-weight: bold;\n"
"min-height:35px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelBalance { /* Available Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:16px;\n"
"color:#183862;\n"
"margin-left:0px;\n"
"    font-weight: bold;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelWatchAvailable { /* Watch-only Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-siz"
                        "e:12px;\n"
"margin-left:16px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelPendingText { /* Pending Balance Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"font-size:14px;\n"
"font-Weight:bold;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelUnconfirmed { /* Pending Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:14px;\n"
"font-weight:bold;\n"
"margin-left:0px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelWatchPending { /* Watch-only Pending Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:12px;\n"
"margin-left:16px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelImmatureText { /* Immature Balance Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"font-size:14px;\n"
"font-weight:bold;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame"
                        "#frame .QLabel#labelImmature { /* Immature Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:14px;\n"
"font-weight:bold;\n"
"margin-left:0px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelWatchImmature { /* Watch-only Immature Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:12px;\n"
"margin-left:16px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelTotalText { /* Total Balance Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"font-size:14px;\n"
"font-weight:bold;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelTotal { /* Total Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:14px;\n"
"font-weight:bold;\n"
"margin-left:0px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame .QLabel#labelWatchTotal { /* Watch-only Total Balance */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"font-size:12px;\n"
"margin-left:16p"
                        "x;\n"
"}\n"
"\n"
"/* PRIVATESEND WIDGET */\n"
"\n"
"QWidget .QFrame#framePrivateSend { /* PrivateSend Widget */\n"
"background-color:transparent;\n"
"max-width: 451px;\n"
"min-width: 451px;\n"
"max-height: 350px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QWidget#layoutWidgetPrivateSendHeader { /* PrivateSend Header */\n"
"max-width: 421px;\n"
"min-width: 421px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QLabel#labelPrivateSendHeader { /* PrivateSend Header */\n"
"qproperty-alignment: 'AlignVCenter | AlignCenter';\n"
"max-width: 421px;\n"
"min-width: 421px;\n"
"background-color:#183862;\n"
"color:#fff;\n"
"margin-right: 5px;\n"
"padding-right: 5px;\n"
"font-weight:bold;\n"
"font-size:14px;\n"
"min-height:35px;\n"
"max-height:35px;\n"
"}\n"
"/******************************************************************/\n"
"QWidget .QFrame#framePrivateSend .QLabel#labelPrivateSendSyncStatus { /* PrivateSend Sync Status */\n"
"qproperty-alignment: 'AlignVCenter | AlignLeft';\n"
"margin-left:2px;\n"
"padding-rig"
                        "ht:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget {\n"
"max-width: 451px;\n"
"max-height: 175px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget > .QLabel {\n"
"min-width:175px;\n"
"font-weight:normal;\n"
"min-height:25px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelPrivateSendEnabledText { /* PrivateSend Enabled Status Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelPrivateSendEnabled { /* PrivateSend Enabled Status */\n"
"\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelCompletitionText { /* PrivateSend Completion Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-ri"
                        "ght:5px;\n"
"\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QProgressBar#privateSendProgress { /* PrivateSend Completion */\n"
"border: 1px solid #818181;\n"
"border-radius: 1px;\n"
"margin-right:43px;\n"
"text-align: right;\n"
"color:#818181;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QProgressBar#privateSendProgress::chunk {\n"
"background-color: #183862;\n"
"width:1px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelAnonymizedText { /* PrivateSend Balance Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelAnonymized { /* PrivateSend Balance */\n"
"\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelAmountAndRoundsText { /* PrivateSend Amount and Rounds Label */\n"
"qp"
                        "roperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelAmountRounds { /* PrivateSend Amount and Rounds */\n"
"\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelSubmittedDenomText { /* PrivateSend Submitted Denom Label */\n"
"qproperty-alignment: 'AlignVCenter | AlignRight';\n"
"min-width:160px;\n"
"background-color:#F8F6F6;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend #privateSendFormLayoutWidget .QLabel#labelSubmittedDenom { /* PrivateSend Submitted Denom */\n"
"\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QWidget#layoutWidgetLastMessageAndButtons {\n"
"max-width: 451px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QLabel#labelPrivateSendLastMessage { /* PrivateSend Status Notifications */\n"
"qproperty-alignment: 'AlignVCenter | AlignCe"
                        "nter';\n"
"min-width: 288px;\n"
"min-height: 43px;\n"
"font-size:11px;\n"
"color:#818181;\n"
"}\n"
"\n"
"/* PRIVATESEND BUTTONS */\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton { /* PrivateSend Buttons - General Attributes */\n"
"border:0px solid #ffffff;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend QPushButton:focus {\n"
"border:none;\n"
"outline:none;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#togglePrivateSend { /* Start PrivateSend Mixing */\n"
"min-height: 40px;\n"
"font-size:15px;\n"
"font-weight:normal;\n"
"color:#ffffff;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"padding-top:5px;\n"
"padding-bottom:6px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#togglePrivateSend:hover {\n"
"\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendAuto { /* Try Mix Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
""
                        "border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"min-height:25px;\n"
"font-size:9px;\n"
"padding:0px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendAuto:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendAuto:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendReset { /* Reset Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"min-height:25px;\n"
"font-size:9px;\n"
"padding:0px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendReset:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, sto"
                        "p: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendReset:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendInfo { /* Info Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"min-height:25px;\n"
"font-size:9px;\n"
"padding:0px;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendInfo:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget .QFrame#framePrivateSend .QPushButton#privateSendInfo:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"/* R"
                        "ECENT TRANSACTIONS */\n"
"\n"
"QWidget .QFrame#frame_2 { /* Transactions Widget */\n"
"min-width:410px;\n"
"margin-right:20px;\n"
"margin-left:0;\n"
"margin-top:15px;\n"
"background-repeat:none;\n"
"}\n"
"\n"
"QWidget .QFrame#frame_2 .QLabel#label_4 { /* Recent Transactions Label */\n"
"min-width:180px;\n"
"color:#999;\n"
"margin-left:0px;\n"
"margin-top:30px;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"font-weight:normal;\n"
"font-size:18px;\n"
"font-weight:bold;\n"
"min-height:24px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame_2 .QLabel#labelTransactionsStatus { /* Recent Transactions Sync Status */\n"
"qproperty-alignment: 'AlignBottom | AlignRight';\n"
"min-width:93px;\n"
"margin-top:83px;\n"
"margin-left:16px;\n"
"margin-right:5px;\n"
"min-height:16px;\n"
"}\n"
"\n"
"QWidget .QFrame#frame_2 QListView { /* SUQA Transaction List */\n"
"font-weight:normal;\n"
"font-size:14px;\n"
"max-width:500px;\n"
"margin-top:12px;\n"
"margin-left:0px; /* CSS Voodoo - set to -66px to hide default transaction icons */\n"
"}\n"
""
                        "\n"
"/* SEND DIALOG */\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl { /* Coin Control Section */\n"
"\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl > .QLabel { /* Default Font Color and  Size */\n"
"font-weight:normal;\n"
"color: #999;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl .QPushButton#pushButtonCoinControl { /* Coin Control Inputs Button */\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"min-height:25px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl .QLabel#labelCoinControlFeatures { /* Coin Control Header */\n"
"color:#999;\n"
"font-weight:normal;\n"
"font-size:14px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl .QWidget#widgetCoinControl { /* Coin Control Inputs */\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl .QWidget#widgetCoinControl > .QLabel { /* Coin Control Inputs Labels */\n"
"padding:2px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl .QCheckBox#checkBoxCoinControlChang"
                        "e { /* Custom Change Label */\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl .QValidatedLineEdit#lineEditCoinControlChange { /* Custom Change Address */\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QFrame#frameCoinControl .QLabel#labelCoinControlChangeLabel { /* Custom Change Address Validation Label */\n"
"font-weight:normal;\n"
"qproperty-margin:-6;\n"
"margin-right:112px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QScrollArea#scrollArea .QWidget#scrollAreaWidgetContents { /* Send To Widget */\n"
"background:transparent;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QPushButton#sendButton { /* Send Button */\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QPushButton#clearButton { /* Clear Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
""
                        "}\n"
"\n"
"QDialog#SendCoinsDialog .QPushButton#clearButton:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QPushButton#clearButton:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QPushButton#addButton { /* Add Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QPushButton#addButton:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QPushButton#add"
                        "Button:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QCheckBox#checkUsePrivateSend { /* PrivateSend Checkbox */\n"
"color:#616161;\n"
"font-weight:bold;\n"
"background: qradialgradient(cx:0.5, cy:0.5, radius: 0.5, fx:0.5, fy:0.5, stop:0 rgba(248, 246, 246, 128), stop: 1 rgba(0, 0, 0, 0));\n"
"border-radius:5px;\n"
"padding-top:20px;\n"
"padding-bottom:18px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog .QCheckBox#checkUseInstantSend { /* InstantSend Checkbox */\n"
"color:#616161;\n"
"font-weight:bold;\n"
"background: qradialgradient(cx:0.5, cy:0.5, radius: 0.5, fx:0.5, fy:0.5, stop:0 rgba(248, 246, 246, 128), stop: 1 rgba(0, 0, 0, 0));\n"
"border-radius:5px;\n"
"padding-top:20px;\n"
"padding-bottom:18px;\n"
"margin-left:10px;\n"
"margin-right:20px;\n"
"}\n"
"\n"
"/* This QLabel uses name = \"label\" which conflicts with Address Book -> New Address */\n"
"/* To maximize backwards compatibility this formatting has been removed */\n"
"\n"
"QDialog#SendCoinsDialog QLabel#label {\n"
"/*ma"
                        "rgin-left:20px;\n"
"margin-right:-2px;\n"
"padding-right:-2px;\n"
"color:#616161;\n"
"font-size:14px;\n"
"font-weight:bold;\n"
"border-radius:5px;\n"
"padding-top:20px;\n"
"padding-bottom:20px;*/\n"
"min-height:27px;\n"
"}\n"
"\n"
"QDialog#SendCoinsDialog QLabel#labelBalance {\n"
"margin-left:0px;\n"
"padding-left:0px;\n"
"color:#333333;\n"
"/* font-weight:bold;\n"
"border-radius:5px;\n"
"padding-top:20px;\n"
"padding-bottom:20px; */\n"
"min-height:27px;\n"
"}\n"
"\n"
"#checkboxSubtractFeeFromAmount {\n"
"padding-left:10px;\n"
"}\n"
"\n"
"\n"
"/* SEND COINS ENTRY */\n"
"\n"
"QStackedWidget#SendCoinsEntry .QFrame#SendCoins > .QLabel { /* Send Coin Entry Labels */\n"
"background-color:#F8F6F6;\n"
"min-width:102px;\n"
"font-weight:normal;\n"
"/*font-size:11px;*/\n"
"color:#333;\n"
"min-height:25px;\n"
"margin-right:5px;\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry .QFrame#SendCoins .QLabel#amountLabel {\n"
"color: #fff;\n"
"background-color:#999;\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry"
                        " .QValidatedLineEdit#payTo { /* Pay To Input Field */\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry .QToolButton { /* General Settings for Pay To Icons */\n"
"padding-left:5px;\n"
"padding-right:5px;\n"
"border: 0;\n"
"outline: 0;\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry .QToolButton#addressBookButton { /* Address Book Button */\n"
"padding-left:10px;\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry .QToolButton#addressBookButton {\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry .QToolButton#pasteButton {\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry .QToolButton#deleteButton {\n"
"}\n"
"\n"
"QStackedWidget#SendCoinsEntry .QLineEdit#addAsLabel { /* Pay To Input Field */\n"
"}\n"
"\n"
"/* COIN CONTROL POPUP */\n"
"\n"
"QDialog#CoinControlDialog { /* Coin Control Dialog Window */\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlQuantityText { /* Coin Control Quantity Label */\n"
"min-height:30px;\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labe"
                        "lCoinControlQuantity { /* Coin Control Quantity */\n"
"min-height:30px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlBytesText { /* Coin Control Bytes Label */\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlBytes { /* Coin Control Bytes */\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlAmountText { /* Coin Control Amount Label */\n"
"min-height:30px;\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlAmount { /* Coin Control Amount */\n"
"min-height:30px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlPriorityText { /* Coin Control Priority Label */\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlPriority { /* Coin Control Priority */\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlFeeText { /* Coin Control Fee Label */\n"
"min-height:30px;\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinCo"
                        "ntrolFee { /* Coin Control Fee */\n"
"min-height:30px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlLowOutputText { /* Coin Control Low Output Label */\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlLowOutput { /* Coin Control Low Output */\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlAfterFeeText { /* Coin Control After Fee Label */\n"
"min-height:30px;\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlAfterFee { /* Coin Control After Fee */\n"
"min-height:30px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlChangeText { /* Coin Control Change Label */\n"
"padding-left:15px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QLabel#labelCoinControlChange { /* Coin Control Change */\n"
"\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QFrame#frame .QPushButton#pushButtonSelectAll { /* (un)select all button */\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"min-height:25px;\n"
"}\n"
"\n"
""
                        "QDialog#CoinControlDialog .QFrame#frame .QPushButton#pushButtonToggleLock { /* Toggle lock state button */\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"min-height:25px;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QDialogButtonBox#buttonBox QPushButton { /* Coin Control 'OK' button */\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QFrame#frame .QRadioButton#radioTreeMode { /* Coin Control Tree Mode Selector */\n"
"color:#818181;\n"
"background-color:transparent;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .QFrame#frame .QRadioButton#radioListMode { /* Coin Control List Mode Selector */\n"
"color:#818181;\n"
"background-color:transparent;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog QHeaderView::section:first { /* Bug Fix: the number \"1\" displays in this table for some reason... */\n"
"color:transparent;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .CoinControlTreeWidget#treeWidget { /* Coin Control Widget Container */\n"
"outline:0;\n"
"background-color:#ffffff;\n"
"border:0px solid #818181;\n"
"}\n"
"\n"
"QDialog#CoinCo"
                        "ntrolDialog .CoinControlTreeWidget#treeWidget::item {\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .CoinControlTreeWidget#treeWidget::item:selected { /* Coin Control Item (selected) */\n"
"background-color:#f7f7f7;\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .CoinControlTreeWidget#treeWidget::item:checked { /* Coin Control Item (checked) */\n"
"background-color:#f7f7f7;\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .CoinControlTreeWidget#treeWidget::branch:selected { /* Coin Control Branch Icon */\n"
"background-image: url(':/images/light/drkblue_qtreeview_selected');\n"
"background-repeat:no-repeat;\n"
"background-position:center;\n"
"background-color:#f7f7f7;\n"
"color:#333;\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .CoinControlTreeWidget#treeWidget::branch:checked { /* Coin Control Branch Icon */\n"
"background-image: url(':/images/light/drkblue_qtreeview_selected');\n"
"background-repeat:no-repeat;\n"
"background-position:center;\n"
"background-color:#f7f7f7;\n"
"color:#333;\n"
"}\n"
"\n"
""
                        "QDialog#CoinControlDialog .CoinControlTreeWidget#treeWidget::seperator {\n"
"\n"
"}\n"
"\n"
"QDialog#CoinControlDialog .CoinControlTreeWidget#treeWidget::indicator { /* Coin Control Widget Checkbox */\n"
"\n"
"}\n"
"\n"
"/* RECEIVE COINS */\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame2 .QLabel#label_2 { /* Label Label */\n"
"background-color:#F8F6F6;\n"
"border: 1px solid #fff;\n"
"min-width:102px;\n"
"color:#333;\n"
"/*font-weight:bold;\n"
"font-size:11px;*/\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame2 .QLabel#label { /* Amount Label */\n"
"background-color:#999;\n"
"border: 1px solid #fff;\n"
"min-width:102px;\n"
"color:#ffffff;\n"
"/*font-weight:bold;\n"
"font-size:11px;*/\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame2 .QLabel#label_3 { /* Message Label */\n"
"background-color:#F8F6F6;\n"
"border: 1px solid #fff;\n"
"min-width:102px;\n"
"color:#333;\n"
"/*font-weight:bold;\n"
"font-size:11px;*/\n"
"padding-right:5px;\n"
"}\n"
"\n"
"QWi"
                        "dget#ReceiveCoinsDialog .QFrame#frame2 QPushButton#clearButton { /* Clear Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame2 QPushButton#clearButton:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame2 QPushButton#clearButton:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame QPushButton#showRequestButton { /* Show Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebe"
                        "beb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame QPushButton#showRequestButton:hover {\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame QPushButton#showRequestButton:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame QPushButton#removeRequestButton { /* Remove Button */\n"
"background-color:qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(250, 250, 250, 128), stop: .95 rgba(250, 250, 250, 255), stop: 1 #ebebeb);\n"
"border:1px solid #d2d2d2;\n"
"color:#616161;\n"
"padding-left:10px;\n"
"padding-right:10px;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame QPushButton#removeRequestButton:hover {\n"
"background-color:qlineargradient(x1"
                        ": 0, y1: 0, x2: 0, y2: 1, stop: .01 #f6f6f6, stop: .1 rgba(240, 240, 240, 255), stop: .95 rgba(240, 240, 240, 255), stop: 1 #ebebeb);\n"
"color:#333;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame QPushButton#removeRequestButton:pressed {\n"
"border:1px solid #9e9e9e;\n"
"}\n"
"\n"
"QWidget#ReceiveCoinsDialog .QFrame#frame .QLabel#label_6 { /* Requested Payments History Label */\n"
"color:#999;\n"
"font-weight:normal;\n"
"font-size:14px;\n"
"}\n"
"\n"
"/* RECEIVE COINS DIALOG */\n"
"\n"
"QDialog#ReceiveRequestDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#ReceiveRequestDialog QTextEdit { /* Contents of Receive Coin Dialog */\n"
"border:1px solid #d7d7d7;\n"
"}\n"
"\n"
"/* TRANSACTIONS PAGE */\n"
"\n"
"TransactionView QLineEdit { /* Filters */\n"
"margin-bottom:2px;\n"
"margin-right:1px;\n"
"min-width:111px;\n"
"text-align:center;\n"
"}\n"
"\n"
"TransactionView QLineEdit#addressWidget { /* Address Filter */\n"
"margin-bottom:2px;\n"
"margin-right:1px;\n"
"min-width:405px;\n"
"text-align:"
                        "center;\n"
"}\n"
"\n"
"TransactionView QLineEdit#amountWidget { /* Amount Filter */\n"
"margin-bottom:2px;\n"
"margin-right:1px;\n"
"max-width:100px;\n"
"text-align:center;\n"
"}\n"
"\n"
"TransactionView QComboBox {\n"
"margin-bottom:1px;\n"
"margin-right:1px;\n"
"}\n"
"\n"
"QLabel#transactionSumLabel { /* Example of setObjectName for widgets without name */\n"
"color:#333333;\n"
"font-weight:bold;\n"
"}\n"
" \n"
"QLabel#transactionSum { /* Example of setObjectName for widgets without name */\n"
"color:#333333;\n"
"}\n"
"\n"
"/* TRANSACTION DETAIL DIALOG */\n"
"\n"
"QDialog#TransactionDescDialog {\n"
"background-color:#F8F6F6;\n"
"}\n"
"\n"
"QDialog#TransactionDescDialog QTextEdit { /* Contents of Receive Coin Dialog */\n"
"border:1px solid #d7d7d7;\n"
"\n"
"}\n"
"\n"
"\n"
""));
        verticalLayout_2 = new QVBoxLayout(RPCConsole);
        verticalLayout_2->setObjectName(QStringLiteral("verticalLayout_2"));
        tabWidget = new QTabWidget(RPCConsole);
        tabWidget->setObjectName(QStringLiteral("tabWidget"));
        tab_info = new QWidget();
        tab_info->setObjectName(QStringLiteral("tab_info"));
        gridLayout = new QGridLayout(tab_info);
        gridLayout->setObjectName(QStringLiteral("gridLayout"));
        gridLayout->setHorizontalSpacing(12);
        label_9 = new QLabel(tab_info);
        label_9->setObjectName(QStringLiteral("label_9"));
        QFont font;
        label_9->setFont(font);

        gridLayout->addWidget(label_9, 0, 0, 1, 1);

        label_5 = new QLabel(tab_info);
        label_5->setObjectName(QStringLiteral("label_5"));

        gridLayout->addWidget(label_5, 1, 0, 1, 1);

        clientName = new QLabel(tab_info);
        clientName->setObjectName(QStringLiteral("clientName"));
        clientName->setCursor(QCursor(Qt::IBeamCursor));
        clientName->setTextFormat(Qt::PlainText);
        clientName->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(clientName, 1, 1, 1, 1);

        label_6 = new QLabel(tab_info);
        label_6->setObjectName(QStringLiteral("label_6"));

        gridLayout->addWidget(label_6, 2, 0, 1, 1);

        clientVersion = new QLabel(tab_info);
        clientVersion->setObjectName(QStringLiteral("clientVersion"));
        clientVersion->setCursor(QCursor(Qt::IBeamCursor));
        clientVersion->setTextFormat(Qt::PlainText);
        clientVersion->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(clientVersion, 2, 1, 1, 1);

        label_14 = new QLabel(tab_info);
        label_14->setObjectName(QStringLiteral("label_14"));
        label_14->setIndent(10);

        gridLayout->addWidget(label_14, 3, 0, 1, 1);

        openSSLVersion = new QLabel(tab_info);
        openSSLVersion->setObjectName(QStringLiteral("openSSLVersion"));
        openSSLVersion->setCursor(QCursor(Qt::IBeamCursor));
        openSSLVersion->setTextFormat(Qt::PlainText);
        openSSLVersion->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(openSSLVersion, 3, 1, 1, 1);

        label_berkeleyDBVersion = new QLabel(tab_info);
        label_berkeleyDBVersion->setObjectName(QStringLiteral("label_berkeleyDBVersion"));
        label_berkeleyDBVersion->setIndent(10);

        gridLayout->addWidget(label_berkeleyDBVersion, 4, 0, 1, 1);

        berkeleyDBVersion = new QLabel(tab_info);
        berkeleyDBVersion->setObjectName(QStringLiteral("berkeleyDBVersion"));
        berkeleyDBVersion->setCursor(QCursor(Qt::IBeamCursor));
        berkeleyDBVersion->setTextFormat(Qt::PlainText);
        berkeleyDBVersion->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(berkeleyDBVersion, 4, 1, 1, 1);

        label_12 = new QLabel(tab_info);
        label_12->setObjectName(QStringLiteral("label_12"));

        gridLayout->addWidget(label_12, 5, 0, 1, 1);

        buildDate = new QLabel(tab_info);
        buildDate->setObjectName(QStringLiteral("buildDate"));
        buildDate->setCursor(QCursor(Qt::IBeamCursor));
        buildDate->setTextFormat(Qt::PlainText);
        buildDate->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(buildDate, 5, 1, 1, 1);

        label_13 = new QLabel(tab_info);
        label_13->setObjectName(QStringLiteral("label_13"));

        gridLayout->addWidget(label_13, 6, 0, 1, 1);

        startupTime = new QLabel(tab_info);
        startupTime->setObjectName(QStringLiteral("startupTime"));
        startupTime->setCursor(QCursor(Qt::IBeamCursor));
        startupTime->setTextFormat(Qt::PlainText);
        startupTime->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(startupTime, 6, 1, 1, 1);

        label_11 = new QLabel(tab_info);
        label_11->setObjectName(QStringLiteral("label_11"));
        label_11->setFont(font);

        gridLayout->addWidget(label_11, 7, 0, 1, 1);

        label_8 = new QLabel(tab_info);
        label_8->setObjectName(QStringLiteral("label_8"));

        gridLayout->addWidget(label_8, 8, 0, 1, 1);

        networkName = new QLabel(tab_info);
        networkName->setObjectName(QStringLiteral("networkName"));
        networkName->setCursor(QCursor(Qt::IBeamCursor));
        networkName->setTextFormat(Qt::PlainText);
        networkName->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(networkName, 8, 1, 1, 1);

        label_7 = new QLabel(tab_info);
        label_7->setObjectName(QStringLiteral("label_7"));

        gridLayout->addWidget(label_7, 9, 0, 1, 1);

        numberOfConnections = new QLabel(tab_info);
        numberOfConnections->setObjectName(QStringLiteral("numberOfConnections"));
        numberOfConnections->setCursor(QCursor(Qt::IBeamCursor));
        numberOfConnections->setTextFormat(Qt::PlainText);
        numberOfConnections->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(numberOfConnections, 9, 1, 1, 1);

        label_10 = new QLabel(tab_info);
        label_10->setObjectName(QStringLiteral("label_10"));
        label_10->setFont(font);

        gridLayout->addWidget(label_10, 10, 0, 1, 1);

        label_3 = new QLabel(tab_info);
        label_3->setObjectName(QStringLiteral("label_3"));

        gridLayout->addWidget(label_3, 11, 0, 1, 1);

        numberOfBlocks = new QLabel(tab_info);
        numberOfBlocks->setObjectName(QStringLiteral("numberOfBlocks"));
        numberOfBlocks->setCursor(QCursor(Qt::IBeamCursor));
        numberOfBlocks->setTextFormat(Qt::PlainText);
        numberOfBlocks->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(numberOfBlocks, 11, 1, 1, 1);

        label_2 = new QLabel(tab_info);
        label_2->setObjectName(QStringLiteral("label_2"));

        gridLayout->addWidget(label_2, 12, 0, 1, 1);

        lastBlockTime = new QLabel(tab_info);
        lastBlockTime->setObjectName(QStringLiteral("lastBlockTime"));
        lastBlockTime->setCursor(QCursor(Qt::IBeamCursor));
        lastBlockTime->setTextFormat(Qt::PlainText);
        lastBlockTime->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout->addWidget(lastBlockTime, 12, 1, 1, 1);

        verticalSpacer_2 = new QSpacerItem(20, 20, QSizePolicy::Minimum, QSizePolicy::Expanding);

        gridLayout->addItem(verticalSpacer_2, 13, 0, 1, 1);

        labelDebugLogfile = new QLabel(tab_info);
        labelDebugLogfile->setObjectName(QStringLiteral("labelDebugLogfile"));
        labelDebugLogfile->setFont(font);

        gridLayout->addWidget(labelDebugLogfile, 14, 0, 1, 1);

        openDebugLogfileButton = new QPushButton(tab_info);
        openDebugLogfileButton->setObjectName(QStringLiteral("openDebugLogfileButton"));
        openDebugLogfileButton->setAutoDefault(false);

        gridLayout->addWidget(openDebugLogfileButton, 15, 0, 1, 1);

        verticalSpacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        gridLayout->addItem(verticalSpacer, 16, 0, 1, 1);

        gridLayout->setColumnStretch(1, 1);
        tabWidget->addTab(tab_info, QString());
        tab_console = new QWidget();
        tab_console->setObjectName(QStringLiteral("tab_console"));
        verticalLayout_3 = new QVBoxLayout(tab_console);
        verticalLayout_3->setSpacing(3);
        verticalLayout_3->setObjectName(QStringLiteral("verticalLayout_3"));
        messagesWidget = new QTextEdit(tab_console);
        messagesWidget->setObjectName(QStringLiteral("messagesWidget"));
        messagesWidget->setMinimumSize(QSize(0, 100));
        messagesWidget->setReadOnly(true);
        messagesWidget->setProperty("tabKeyNavigation", QVariant(false));
        messagesWidget->setProperty("columnCount", QVariant(2));

        verticalLayout_3->addWidget(messagesWidget);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setSpacing(3);
        horizontalLayout->setObjectName(QStringLiteral("horizontalLayout"));
        label = new QLabel(tab_console);
        label->setObjectName(QStringLiteral("label"));
        label->setText(QStringLiteral(">"));

        horizontalLayout->addWidget(label);

        lineEdit = new QLineEdit(tab_console);
        lineEdit->setObjectName(QStringLiteral("lineEdit"));

        horizontalLayout->addWidget(lineEdit);

        clearButton = new QPushButton(tab_console);
        clearButton->setObjectName(QStringLiteral("clearButton"));
        clearButton->setMaximumSize(QSize(24, 24));
        QIcon icon;
        icon.addFile(QStringLiteral(":/icons/remove"), QSize(), QIcon::Normal, QIcon::Off);
        clearButton->setIcon(icon);
        clearButton->setShortcut(QStringLiteral("Ctrl+L"));
        clearButton->setAutoDefault(false);

        horizontalLayout->addWidget(clearButton);


        verticalLayout_3->addLayout(horizontalLayout);

        tabWidget->addTab(tab_console, QString());
        tab_nettraffic = new QWidget();
        tab_nettraffic->setObjectName(QStringLiteral("tab_nettraffic"));
        horizontalLayout_3 = new QHBoxLayout(tab_nettraffic);
        horizontalLayout_3->setObjectName(QStringLiteral("horizontalLayout_3"));
        verticalLayout_4 = new QVBoxLayout();
        verticalLayout_4->setObjectName(QStringLiteral("verticalLayout_4"));
        trafficGraph = new TrafficGraphWidget(tab_nettraffic);
        trafficGraph->setObjectName(QStringLiteral("trafficGraph"));
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(trafficGraph->sizePolicy().hasHeightForWidth());
        trafficGraph->setSizePolicy(sizePolicy);

        verticalLayout_4->addWidget(trafficGraph);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QStringLiteral("horizontalLayout_2"));
        sldGraphRange = new QSlider(tab_nettraffic);
        sldGraphRange->setObjectName(QStringLiteral("sldGraphRange"));
        sldGraphRange->setMinimum(1);
        sldGraphRange->setMaximum(288);
        sldGraphRange->setPageStep(12);
        sldGraphRange->setValue(6);
        sldGraphRange->setOrientation(Qt::Horizontal);

        horizontalLayout_2->addWidget(sldGraphRange);

        lblGraphRange = new QLabel(tab_nettraffic);
        lblGraphRange->setObjectName(QStringLiteral("lblGraphRange"));
        lblGraphRange->setMinimumSize(QSize(100, 0));
        lblGraphRange->setAlignment(Qt::AlignCenter);

        horizontalLayout_2->addWidget(lblGraphRange);

        btnClearTrafficGraph = new QPushButton(tab_nettraffic);
        btnClearTrafficGraph->setObjectName(QStringLiteral("btnClearTrafficGraph"));
        btnClearTrafficGraph->setAutoDefault(false);

        horizontalLayout_2->addWidget(btnClearTrafficGraph);


        verticalLayout_4->addLayout(horizontalLayout_2);


        horizontalLayout_3->addLayout(verticalLayout_4);

        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QStringLiteral("verticalLayout"));
        groupBox = new QGroupBox(tab_nettraffic);
        groupBox->setObjectName(QStringLiteral("groupBox"));
        verticalLayout_5 = new QVBoxLayout(groupBox);
        verticalLayout_5->setObjectName(QStringLiteral("verticalLayout_5"));
        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QStringLiteral("horizontalLayout_4"));
        line = new QFrame(groupBox);
        line->setObjectName(QStringLiteral("line"));
        QSizePolicy sizePolicy1(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(0);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(line->sizePolicy().hasHeightForWidth());
        line->setSizePolicy(sizePolicy1);
        line->setMinimumSize(QSize(10, 0));
        QPalette palette;
        QBrush brush(QColor(0, 255, 0, 255));
        brush.setStyle(Qt::SolidPattern);
        palette.setBrush(QPalette::Active, QPalette::Light, brush);
        palette.setBrush(QPalette::Inactive, QPalette::Light, brush);
        palette.setBrush(QPalette::Disabled, QPalette::Light, brush);
        line->setPalette(palette);
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);

        horizontalLayout_4->addWidget(line);

        label_16 = new QLabel(groupBox);
        label_16->setObjectName(QStringLiteral("label_16"));

        horizontalLayout_4->addWidget(label_16);

        lblBytesIn = new QLabel(groupBox);
        lblBytesIn->setObjectName(QStringLiteral("lblBytesIn"));
        lblBytesIn->setMinimumSize(QSize(50, 0));
        lblBytesIn->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        horizontalLayout_4->addWidget(lblBytesIn);


        verticalLayout_5->addLayout(horizontalLayout_4);

        horizontalLayout_5 = new QHBoxLayout();
        horizontalLayout_5->setObjectName(QStringLiteral("horizontalLayout_5"));
        line_2 = new QFrame(groupBox);
        line_2->setObjectName(QStringLiteral("line_2"));
        sizePolicy1.setHeightForWidth(line_2->sizePolicy().hasHeightForWidth());
        line_2->setSizePolicy(sizePolicy1);
        line_2->setMinimumSize(QSize(10, 0));
        QPalette palette1;
        QBrush brush1(QColor(255, 0, 0, 255));
        brush1.setStyle(Qt::SolidPattern);
        palette1.setBrush(QPalette::Active, QPalette::Light, brush1);
        palette1.setBrush(QPalette::Inactive, QPalette::Light, brush1);
        palette1.setBrush(QPalette::Disabled, QPalette::Light, brush1);
        line_2->setPalette(palette1);
        line_2->setFrameShape(QFrame::HLine);
        line_2->setFrameShadow(QFrame::Sunken);

        horizontalLayout_5->addWidget(line_2);

        label_17 = new QLabel(groupBox);
        label_17->setObjectName(QStringLiteral("label_17"));

        horizontalLayout_5->addWidget(label_17);

        lblBytesOut = new QLabel(groupBox);
        lblBytesOut->setObjectName(QStringLiteral("lblBytesOut"));
        lblBytesOut->setMinimumSize(QSize(50, 0));
        lblBytesOut->setAlignment(Qt::AlignRight|Qt::AlignTrailing|Qt::AlignVCenter);

        horizontalLayout_5->addWidget(lblBytesOut);


        verticalLayout_5->addLayout(horizontalLayout_5);

        verticalSpacer_4 = new QSpacerItem(20, 407, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_5->addItem(verticalSpacer_4);


        verticalLayout->addWidget(groupBox);


        horizontalLayout_3->addLayout(verticalLayout);

        tabWidget->addTab(tab_nettraffic, QString());
        tab_peers = new QWidget();
        tab_peers->setObjectName(QStringLiteral("tab_peers"));
        gridLayout_2 = new QGridLayout(tab_peers);
        gridLayout_2->setObjectName(QStringLiteral("gridLayout_2"));
        peerWidget = new QTableView(tab_peers);
        peerWidget->setObjectName(QStringLiteral("peerWidget"));
        peerWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        peerWidget->setSortingEnabled(true);
        peerWidget->horizontalHeader()->setHighlightSections(false);

        gridLayout_2->addWidget(peerWidget, 0, 0, 2, 1);

        peerHeading = new QLabel(tab_peers);
        peerHeading->setObjectName(QStringLiteral("peerHeading"));
        QSizePolicy sizePolicy2(QSizePolicy::Preferred, QSizePolicy::Minimum);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(peerHeading->sizePolicy().hasHeightForWidth());
        peerHeading->setSizePolicy(sizePolicy2);
        peerHeading->setMinimumSize(QSize(300, 32));
        peerHeading->setFont(font);
        peerHeading->setCursor(QCursor(Qt::IBeamCursor));
        peerHeading->setAlignment(Qt::AlignHCenter|Qt::AlignTop);
        peerHeading->setWordWrap(true);
        peerHeading->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_2->addWidget(peerHeading, 0, 1, 1, 1);

        detailWidget = new QWidget(tab_peers);
        detailWidget->setObjectName(QStringLiteral("detailWidget"));
        detailWidget->setMinimumSize(QSize(300, 0));
        gridLayout_3 = new QGridLayout(detailWidget);
        gridLayout_3->setObjectName(QStringLiteral("gridLayout_3"));
        label_23 = new QLabel(detailWidget);
        label_23->setObjectName(QStringLiteral("label_23"));

        gridLayout_3->addWidget(label_23, 0, 0, 1, 1);

        peerDirection = new QLabel(detailWidget);
        peerDirection->setObjectName(QStringLiteral("peerDirection"));
        peerDirection->setCursor(QCursor(Qt::IBeamCursor));
        peerDirection->setTextFormat(Qt::PlainText);
        peerDirection->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerDirection, 0, 2, 1, 1);

        label_21 = new QLabel(detailWidget);
        label_21->setObjectName(QStringLiteral("label_21"));

        gridLayout_3->addWidget(label_21, 1, 0, 1, 1);

        peerVersion = new QLabel(detailWidget);
        peerVersion->setObjectName(QStringLiteral("peerVersion"));
        peerVersion->setCursor(QCursor(Qt::IBeamCursor));
        peerVersion->setTextFormat(Qt::PlainText);
        peerVersion->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerVersion, 1, 2, 1, 1);

        label_28 = new QLabel(detailWidget);
        label_28->setObjectName(QStringLiteral("label_28"));

        gridLayout_3->addWidget(label_28, 2, 0, 1, 1);

        peerSubversion = new QLabel(detailWidget);
        peerSubversion->setObjectName(QStringLiteral("peerSubversion"));
        peerSubversion->setCursor(QCursor(Qt::IBeamCursor));
        peerSubversion->setTextFormat(Qt::PlainText);
        peerSubversion->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerSubversion, 2, 2, 1, 1);

        label_4 = new QLabel(detailWidget);
        label_4->setObjectName(QStringLiteral("label_4"));

        gridLayout_3->addWidget(label_4, 3, 0, 1, 1);

        peerServices = new QLabel(detailWidget);
        peerServices->setObjectName(QStringLiteral("peerServices"));
        peerServices->setCursor(QCursor(Qt::IBeamCursor));
        peerServices->setTextFormat(Qt::PlainText);
        peerServices->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerServices, 3, 2, 1, 1);

        label_29 = new QLabel(detailWidget);
        label_29->setObjectName(QStringLiteral("label_29"));

        gridLayout_3->addWidget(label_29, 5, 0, 1, 1);

        peerHeight = new QLabel(detailWidget);
        peerHeight->setObjectName(QStringLiteral("peerHeight"));
        peerHeight->setCursor(QCursor(Qt::IBeamCursor));
        peerHeight->setTextFormat(Qt::PlainText);
        peerHeight->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerHeight, 5, 2, 1, 1);

        label_27 = new QLabel(detailWidget);
        label_27->setObjectName(QStringLiteral("label_27"));

        gridLayout_3->addWidget(label_27, 6, 0, 1, 1);

        peerSyncHeight = new QLabel(detailWidget);
        peerSyncHeight->setObjectName(QStringLiteral("peerSyncHeight"));
        peerSyncHeight->setCursor(QCursor(Qt::IBeamCursor));
        peerSyncHeight->setTextFormat(Qt::PlainText);
        peerSyncHeight->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerSyncHeight, 6, 2, 1, 1);

        label_24 = new QLabel(detailWidget);
        label_24->setObjectName(QStringLiteral("label_24"));

        gridLayout_3->addWidget(label_24, 7, 0, 1, 1);

        peerBanScore = new QLabel(detailWidget);
        peerBanScore->setObjectName(QStringLiteral("peerBanScore"));
        peerBanScore->setCursor(QCursor(Qt::IBeamCursor));
        peerBanScore->setTextFormat(Qt::PlainText);
        peerBanScore->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerBanScore, 7, 2, 1, 1);

        label_22 = new QLabel(detailWidget);
        label_22->setObjectName(QStringLiteral("label_22"));

        gridLayout_3->addWidget(label_22, 8, 0, 1, 1);

        peerConnTime = new QLabel(detailWidget);
        peerConnTime->setObjectName(QStringLiteral("peerConnTime"));
        peerConnTime->setCursor(QCursor(Qt::IBeamCursor));
        peerConnTime->setTextFormat(Qt::PlainText);
        peerConnTime->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerConnTime, 8, 2, 1, 1);

        label_15 = new QLabel(detailWidget);
        label_15->setObjectName(QStringLiteral("label_15"));

        gridLayout_3->addWidget(label_15, 9, 0, 1, 1);

        peerLastSend = new QLabel(detailWidget);
        peerLastSend->setObjectName(QStringLiteral("peerLastSend"));
        peerLastSend->setCursor(QCursor(Qt::IBeamCursor));
        peerLastSend->setTextFormat(Qt::PlainText);
        peerLastSend->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerLastSend, 9, 2, 1, 1);

        label_19 = new QLabel(detailWidget);
        label_19->setObjectName(QStringLiteral("label_19"));

        gridLayout_3->addWidget(label_19, 10, 0, 1, 1);

        peerLastRecv = new QLabel(detailWidget);
        peerLastRecv->setObjectName(QStringLiteral("peerLastRecv"));
        peerLastRecv->setCursor(QCursor(Qt::IBeamCursor));
        peerLastRecv->setTextFormat(Qt::PlainText);
        peerLastRecv->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerLastRecv, 10, 2, 1, 1);

        label_18 = new QLabel(detailWidget);
        label_18->setObjectName(QStringLiteral("label_18"));

        gridLayout_3->addWidget(label_18, 11, 0, 1, 1);

        peerBytesSent = new QLabel(detailWidget);
        peerBytesSent->setObjectName(QStringLiteral("peerBytesSent"));
        peerBytesSent->setCursor(QCursor(Qt::IBeamCursor));
        peerBytesSent->setTextFormat(Qt::PlainText);
        peerBytesSent->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerBytesSent, 11, 2, 1, 1);

        label_20 = new QLabel(detailWidget);
        label_20->setObjectName(QStringLiteral("label_20"));

        gridLayout_3->addWidget(label_20, 12, 0, 1, 1);

        peerBytesRecv = new QLabel(detailWidget);
        peerBytesRecv->setObjectName(QStringLiteral("peerBytesRecv"));
        peerBytesRecv->setCursor(QCursor(Qt::IBeamCursor));
        peerBytesRecv->setTextFormat(Qt::PlainText);
        peerBytesRecv->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerBytesRecv, 12, 2, 1, 1);

        label_26 = new QLabel(detailWidget);
        label_26->setObjectName(QStringLiteral("label_26"));

        gridLayout_3->addWidget(label_26, 13, 0, 1, 1);

        peerPingTime = new QLabel(detailWidget);
        peerPingTime->setObjectName(QStringLiteral("peerPingTime"));
        peerPingTime->setCursor(QCursor(Qt::IBeamCursor));
        peerPingTime->setTextFormat(Qt::PlainText);
        peerPingTime->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(peerPingTime, 13, 2, 1, 1);

        label_timeoffset = new QLabel(detailWidget);
        label_timeoffset->setObjectName(QStringLiteral("label_timeoffset"));

        gridLayout_3->addWidget(label_timeoffset, 14, 0, 1, 1);

        timeoffset = new QLabel(detailWidget);
        timeoffset->setObjectName(QStringLiteral("timeoffset"));
        timeoffset->setCursor(QCursor(Qt::IBeamCursor));
        timeoffset->setTextFormat(Qt::PlainText);
        timeoffset->setTextInteractionFlags(Qt::LinksAccessibleByMouse|Qt::TextSelectableByKeyboard|Qt::TextSelectableByMouse);

        gridLayout_3->addWidget(timeoffset, 14, 2, 1, 1);

        verticalSpacer_3 = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);

        gridLayout_3->addItem(verticalSpacer_3, 15, 1, 1, 1);


        gridLayout_2->addWidget(detailWidget, 1, 1, 1, 1);

        tabWidget->addTab(tab_peers, QString());

        verticalLayout_2->addWidget(tabWidget);


        retranslateUi(RPCConsole);

        tabWidget->setCurrentIndex(2);


        QMetaObject::connectSlotsByName(RPCConsole);
    } // setupUi

    void retranslateUi(QWidget *RPCConsole)
    {
        RPCConsole->setWindowTitle(QApplication::translate("RPCConsole", "Debug window", 0));
        label_9->setText(QApplication::translate("RPCConsole", "General", 0));
        label_5->setText(QApplication::translate("RPCConsole", "Client name", 0));
        clientName->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_6->setText(QApplication::translate("RPCConsole", "Client version", 0));
        clientVersion->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_14->setText(QApplication::translate("RPCConsole", "Using OpenSSL version", 0));
        openSSLVersion->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_berkeleyDBVersion->setText(QApplication::translate("RPCConsole", "Using BerkeleyDB version", 0));
        berkeleyDBVersion->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_12->setText(QApplication::translate("RPCConsole", "Build date", 0));
        buildDate->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_13->setText(QApplication::translate("RPCConsole", "Startup time", 0));
        startupTime->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_11->setText(QApplication::translate("RPCConsole", "Network", 0));
        label_8->setText(QApplication::translate("RPCConsole", "Name", 0));
        networkName->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_7->setText(QApplication::translate("RPCConsole", "Number of connections", 0));
        numberOfConnections->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_10->setText(QApplication::translate("RPCConsole", "Block chain", 0));
        label_3->setText(QApplication::translate("RPCConsole", "Current number of blocks", 0));
        numberOfBlocks->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_2->setText(QApplication::translate("RPCConsole", "Last block time", 0));
        lastBlockTime->setText(QApplication::translate("RPCConsole", "N/A", 0));
        labelDebugLogfile->setText(QApplication::translate("RPCConsole", "Debug log file", 0));
#ifndef QT_NO_TOOLTIP
        openDebugLogfileButton->setToolTip(QApplication::translate("RPCConsole", "Open the SUQA Core debug log file from the current data directory. This can take a few seconds for large log files.", 0));
#endif // QT_NO_TOOLTIP
        openDebugLogfileButton->setText(QApplication::translate("RPCConsole", "&Open", 0));
        tabWidget->setTabText(tabWidget->indexOf(tab_info), QApplication::translate("RPCConsole", "&Information", 0));
#ifndef QT_NO_TOOLTIP
        clearButton->setToolTip(QApplication::translate("RPCConsole", "Clear console", 0));
#endif // QT_NO_TOOLTIP
        clearButton->setText(QString());
        tabWidget->setTabText(tabWidget->indexOf(tab_console), QApplication::translate("RPCConsole", "&Console", 0));
        btnClearTrafficGraph->setText(QApplication::translate("RPCConsole", "&Clear", 0));
        groupBox->setTitle(QApplication::translate("RPCConsole", "Totals", 0));
        label_16->setText(QApplication::translate("RPCConsole", "Received", 0));
        label_17->setText(QApplication::translate("RPCConsole", "Sent", 0));
        tabWidget->setTabText(tabWidget->indexOf(tab_nettraffic), QApplication::translate("RPCConsole", "&Network Traffic", 0));
        peerHeading->setText(QApplication::translate("RPCConsole", "Select a peer to view detailed information.", 0));
        label_23->setText(QApplication::translate("RPCConsole", "Direction", 0));
        peerDirection->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_21->setText(QApplication::translate("RPCConsole", "Version", 0));
        peerVersion->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_28->setText(QApplication::translate("RPCConsole", "User Agent", 0));
        peerSubversion->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_4->setText(QApplication::translate("RPCConsole", "Services", 0));
        peerServices->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_29->setText(QApplication::translate("RPCConsole", "Starting Height", 0));
        peerHeight->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_27->setText(QApplication::translate("RPCConsole", "Sync Height", 0));
        peerSyncHeight->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_24->setText(QApplication::translate("RPCConsole", "Ban Score", 0));
        peerBanScore->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_22->setText(QApplication::translate("RPCConsole", "Connection Time", 0));
        peerConnTime->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_15->setText(QApplication::translate("RPCConsole", "Last Send", 0));
        peerLastSend->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_19->setText(QApplication::translate("RPCConsole", "Last Receive", 0));
        peerLastRecv->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_18->setText(QApplication::translate("RPCConsole", "Bytes Sent", 0));
        peerBytesSent->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_20->setText(QApplication::translate("RPCConsole", "Bytes Received", 0));
        peerBytesRecv->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_26->setText(QApplication::translate("RPCConsole", "Ping Time", 0));
        peerPingTime->setText(QApplication::translate("RPCConsole", "N/A", 0));
        label_timeoffset->setText(QApplication::translate("RPCConsole", "Time Offset", 0));
        timeoffset->setText(QApplication::translate("RPCConsole", "N/A", 0));
        tabWidget->setTabText(tabWidget->indexOf(tab_peers), QApplication::translate("RPCConsole", "&Peers", 0));
    } // retranslateUi

};

namespace Ui {
    class RPCConsole: public Ui_RPCConsole {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_RPCCONSOLE_H