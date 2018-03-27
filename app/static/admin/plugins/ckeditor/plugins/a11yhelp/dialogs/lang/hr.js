﻿/*
 Copyright (c) 2003-2016, CKSource - Frederico Knabben. All rights reserved.
 For licensing, see LICENSE.md or http://ckeditor.com/license
*/
CKEDITOR.plugins.setLang("a11yhelp", "hr", {
    title: "Upute dostupnosti",
    contents: "Sadržaj pomoći. Za zatvaranje pritisnite ESC.",
    legend: [{
        name: "Općenito",
        items: [{
            name: "Alatna traka",
            legend: "Pritisni ${toolbarFocus} za navigaciju do alatne trake. Pomicanje do prethodne ili sljedeće alatne grupe vrši se pomoću SHIFT+TAB i TAB. Pomicanje do prethodnog ili sljedećeg gumba u alatnoj traci vrši se pomoću lijeve i desne strelice kursora. Pritisnite SPACE ili ENTER za aktivaciju alatne trake."
        }, {
            name: "Dijalog",
            legend: "Inside a dialog, press TAB to navigate to the next dialog element, press SHIFT+TAB to move to the previous dialog element, press ENTER to submit the dialog, press ESC to cancel the dialog. When a dialog has multiple tabs, the tab list can be reached either with ALT+F10 or with TAB as part of the dialog tabbing order. With tab list focused, move to the next and previous tab with RIGHT and LEFT ARROW, respectively."
        }, {
            name: "Kontekstni izbornik",
            legend: "Pritisnite ${contextMenu} ili APPLICATION tipku za otvaranje kontekstnog izbornika. Pomicanje se vrši TAB ili strelicom kursora prema dolje ili SHIFT+TAB ili strelica kursora prema gore. SPACE ili ENTER odabiru opciju izbornika. Otvorite podizbornik trenutne opcije sa  SPACE, ENTER ili desna strelica kursora. Povratak na prethodni izbornik vrši se sa ESC ili lijevom strelicom kursora. Zatvaranje se vrši pritiskom na tipku ESC."
        },
            {
                name: "Lista",
                legend: "Unutar list-boxa, pomicanje na sljedeću stavku vrši se sa TAB ili strelica kursora prema dolje. Na prethodnu sa SHIFT+TAB ili strelica prema gore. Pritiskom na SPACE ili ENTER odabire se stavka ili ESC za zatvaranje."
            }, {
                name: "Traka putanje elemenata",
                legend: "Pritisnite ${elementsPathFocus} za navigaciju po putanji elemenata. Pritisnite TAB ili desnu strelicu kursora za pomicanje na sljedeći element ili SHIFT+TAB ili lijeva strelica kursora za pomicanje na prethodni element. Pritiskom na SPACE ili ENTER vrši se odabir elementa."
            }]
    },
        {
            name: "Naredbe",
            items: [{name: "Vrati naredbu", legend: "Pritisni ${undo}"}, {
                name: "Ponovi naredbu",
                legend: "Pritisni ${redo}"
            }, {name: "Bold naredba", legend: "Pritisni ${bold}"}, {
                name: "Italic naredba",
                legend: "Pritisni ${italic}"
            }, {name: "Underline naredba", legend: "Pritisni ${underline}"}, {
                name: "Link naredba",
                legend: "Pritisni ${link}"
            }, {
                name: "Smanji alatnu traku naredba",
                legend: "Pritisni ${toolbarCollapse}"
            }, {
                name: "Access previous focus space naredba",
                legend: "Pritisni ${accessPreviousSpace} za pristup najbližem nedostupnom razmaku prije kursora, npr.: dva spojena HR elementa. Ponovnim pritiskom dohvatiti će se sljedeći nedostupni razmak."
            },
                {
                    name: "Access next focus space naredba",
                    legend: "Pritisni ${accessNextSpace} za pristup najbližem nedostupnom razmaku nakon kursora, npr.: dva spojena HR elementa. Ponovnim pritiskom dohvatiti će se sljedeći nedostupni razmak."
                }, {name: "Pomoć za dostupnost", legend: "Pritisni ${a11yHelp}"}]
        }],
    backspace: "Backspace",
    tab: "Tab",
    enter: "Enter",
    shift: "Shift",
    ctrl: "Ctrl",
    alt: "Alt",
    pause: "Pause",
    capslock: "Caps Lock",
    escape: "Escape",
    pageUp: "Page Up",
    pageDown: "Page Down",
    end: "End",
    home: "Home",
    leftArrow: "Left Arrow",
    upArrow: "Up Arrow",
    rightArrow: "Right Arrow",
    downArrow: "Down Arrow",
    insert: "Insert",
    "delete": "Delete",
    leftWindowKey: "Left Windows key",
    rightWindowKey: "Right Windows key",
    selectKey: "Select key",
    numpad0: "Numpad 0",
    numpad1: "Numpad 1",
    numpad2: "Numpad 2",
    numpad3: "Numpad 3",
    numpad4: "Numpad 4",
    numpad5: "Numpad 5",
    numpad6: "Numpad 6",
    numpad7: "Numpad 7",
    numpad8: "Numpad 8",
    numpad9: "Numpad 9",
    multiply: "Multiply",
    add: "Add",
    subtract: "Subtract",
    decimalPoint: "Decimal Point",
    divide: "Divide",
    f1: "F1",
    f2: "F2",
    f3: "F3",
    f4: "F4",
    f5: "F5",
    f6: "F6",
    f7: "F7",
    f8: "F8",
    f9: "F9",
    f10: "F10",
    f11: "F11",
    f12: "F12",
    numLock: "Num Lock",
    scrollLock: "Scroll Lock",
    semiColon: "Semicolon",
    equalSign: "Equal Sign",
    comma: "Comma",
    dash: "Dash",
    period: "Period",
    forwardSlash: "Forward Slash",
    graveAccent: "Grave Accent",
    openBracket: "Open Bracket",
    backSlash: "Backslash",
    closeBracket: "Close Bracket",
    singleQuote: "Single Quote"
});