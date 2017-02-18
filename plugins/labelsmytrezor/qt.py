from functools import partial

from PyQt4.QtGui import *
from PyQt4.QtCore import *

from electrum.plugins import hook
from electrum.i18n import _
from electrum_gui.qt import EnterButton
from electrum_gui.qt.util import ThreadedButton, Buttons
from electrum_gui.qt.util import WindowModalDialog, OkButton

from labelsmytrezor import LabelsMyTrezorPlugin


class Plugin(LabelsMyTrezorPlugin):

    def __init__(self, *args):
        LabelsMyTrezorPlugin.__init__(self, *args)
        self.obj = QObject()

    def requires_settings(self):
        return True

    def settings_widget(self, window):
        return EnterButton(_('Settings'),
                           partial(self.settings_dialog, window))

    def settings_dialog(self, window):
        wallet = window.parent().wallet
        d = WindowModalDialog(window, _("Label Settings"))
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel("Label sync options:"))
        test = ThreadedButton("Test button",
                              partial(self.encode,
                                      self.account_key,
                                      "test string to encode"))

        test2 = ThreadedButton("Test2 button",
                              partial(self.generate_slip0015_labels, wallet))

        vbox = QVBoxLayout()
        vbox.addWidget(test)
        vbox.addWidget(test2)
        hbox.addLayout(vbox)
        vbox = QVBoxLayout(d)
        vbox.addLayout(hbox)
        vbox.addSpacing(20)
        vbox.addLayout(Buttons(OkButton(d)))
        return bool(d.exec_())

    @hook
    def on_new_window(self, window):
        window.connect(window.app, SIGNAL('labels_changed'), window.update_tabs)
        self.start_wallet(window.wallet)
        self.generate_slip0015_labels(window.wallet)

    @hook
    def on_close_window(self, window):
        self.stop_wallet(window.wallet)
