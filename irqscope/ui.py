"""Minimal IDA-native review tables for the first vertical slice."""

import ida_kernwin


class RowsChooser(ida_kernwin.Choose):
    def __init__(self, title, columns, rows, on_select=None):
        self.rows = rows
        self.on_select = on_select
        ida_kernwin.Choose.__init__(self, title, columns, flags=0)

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        return [str(value) for value in self.rows[n]]

    def OnSelectLine(self, n):
        if self.on_select is not None:
            self.on_select(n)
        return ida_kernwin.Choose.NOTHING_CHANGED


def show_rows(title, columns, rows, on_select=None):
    if not rows:
        ida_kernwin.msg(f"[IRQScope] {title}: no results.\n")
        return
    chooser = RowsChooser(title, columns, rows, on_select=on_select)
    chooser.Show()
