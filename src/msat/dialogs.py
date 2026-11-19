"""Modal dialogs for MSAT (all Tkinter Toplevels, grab_set).

Every dialog follows the same pattern: build it, call ``wait_window()``,
then read ``dlg.result`` (``None`` when cancelled).

Validation happens in the dialog; server-side errors are reported by
the caller with a message box.
"""

import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from . import updater
from .dhcp import normalize_mac, validate_ipv4
from .dns import validate_ipv6
from .ldap_client import GROUP_TYPES, is_locked_out


def _center(window, parent):
    """Centre a Toplevel over its parent."""
    window.update_idletasks()
    try:
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        pw, ph = parent.winfo_width(), parent.winfo_height()
    except tk.TclError:
        px, py, pw, ph = 0, 0, 400, 300
    w, h = window.winfo_width(), window.winfo_height()
    x = px + max((pw - w) // 2, 0)
    y = py + max((ph - h) // 2, 0)
    window.geometry("+{}+{}".format(x, y))


class DialogBase(tk.Toplevel):
    """Base class: modal window with OK / Cancel and a ``result``."""

    def __init__(self, parent, title, ok_text="OK"):
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.result = None
        self._ok_text = ok_text
        self.body = ttk.Frame(self, padding=12)
        self.body.pack(fill=tk.BOTH, expand=True)
        self._buttons = ttk.Frame(self, padding=(12, 0, 12, 12))
        self._buttons.pack(fill=tk.X)
        self.protocol("WM_DELETE_WINDOW", self._on_cancel)

    def _finish_buttons(self, extra_buttons=()):
        """Add the standard OK/Cancel row (call after building the body)."""
        for text, command in extra_buttons:
            ttk.Button(self._buttons, text=text, command=command).pack(side=tk.LEFT)
        ttk.Button(self._buttons, text="Cancel", command=self._on_cancel).pack(side=tk.RIGHT)
        ok = ttk.Button(self._buttons, text=self._ok_text, command=self._on_ok)
        ok.pack(side=tk.RIGHT, padx=(0, 6))
        self.bind("<Return>", lambda _e: self._on_ok())
        self.bind("<Escape>", lambda _e: self._on_cancel())
        self.grab_set()
        _center(self, self.master)
        ok.focus_set()

    def _row(self, label, default="", show=None, width=40):
        """One labelled entry row; returns the Entry widget."""
        frame = ttk.Frame(self.body)
        frame.pack(fill=tk.X, pady=3)
        ttk.Label(frame, text=label, width=18, anchor=tk.W).pack(side=tk.LEFT)
        entry = ttk.Entry(frame, width=width, show=show) if show else ttk.Entry(frame, width=width)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        if default:
            entry.insert(0, default)
        return entry

    def _combo_row(self, label, values, default="", width=38):
        frame = ttk.Frame(self.body)
        frame.pack(fill=tk.X, pady=3)
        ttk.Label(frame, text=label, width=18, anchor=tk.W).pack(side=tk.LEFT)
        combo = ttk.Combobox(frame, values=list(values), width=width)
        combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        if default:
            combo.set(default)
        return combo

    def _on_ok(self):
        if self.validate():
            self.result = self.collect()
            self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()

    def validate(self):
        return True

    def collect(self):
        return {}


def _need(entry, label):
    value = entry.get().strip()
    if not value:
        messagebox.showwarning("Missing value", "{} is required.".format(label),
                               parent=entry.winfo_toplevel())
        entry.focus_set()
        return None
    return value


# --------------------------------------------------------------------------
# AD object creation
# --------------------------------------------------------------------------

class NewUserDialog(DialogBase):
    def __init__(self, parent, ou_dn):
        super().__init__(parent, "New User", ok_text="Create")
        self.sam = self._row("Username (sAMAccountName)")
        self.given = self._row("First name")
        self.sn = self._row("Last name")
        self.display = self._row("Display name")
        self.password = self._row("Password", show="*")
        self.confirm = self._row("Confirm password", show="*")
        self.ou = self._row("Organizational Unit (DN)", ou_dn, width=40)
        self.must_change = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.body, text="User must change password at next logon",
                        variable=self.must_change).pack(anchor=tk.W, pady=4)
        self._finish_buttons()

    def validate(self):
        if _need(self.sam, "Username") is None:
            return False
        sam = self.sam.get().strip()
        if any(c in sam for c in ' "/\\[]:;|=,+*?<>@'):
            messagebox.showwarning("Invalid username",
                                   "sAMAccountName may not contain spaces or "
                                   '"/\\[]:;|=,+*?<>@ characters.',
                                   parent=self)
            return False
        pw = self.password.get()
        if not pw:
            messagebox.showwarning("Missing value", "Password is required "
                                   "(the account is created enabled).",
                                   parent=self)
            return False
        if pw != self.confirm.get():
            messagebox.showwarning("Password mismatch",
                                   "The two passwords do not match.", parent=self)
            return False
        if _need(self.ou, "Organizational Unit") is None:
            return False
        return True

    def collect(self):
        return {
            "sam": self.sam.get().strip(),
            "given": self.given.get().strip(),
            "sn": self.sn.get().strip(),
            "display": self.display.get().strip(),
            "password": self.password.get(),
            "ou": self.ou.get().strip(),
            "must_change": self.must_change.get(),
        }


class NewComputerDialog(DialogBase):
    def __init__(self, parent, ou_dn):
        super().__init__(parent, "New Computer", ok_text="Create")
        self.name = self._row("Computer name")
        self.description = self._row("Description")
        self.ou = self._row("Organizational Unit (DN)", ou_dn, width=40)
        self._finish_buttons()

    def validate(self):
        return _need(self.name, "Computer name") is not None \
            and _need(self.ou, "Organizational Unit") is not None

    def collect(self):
        return {"name": self.name.get().strip(),
                "description": self.description.get().strip(),
                "ou": self.ou.get().strip()}


class NewGroupDialog(DialogBase):
    def __init__(self, parent, ou_dn):
        super().__init__(parent, "New Group", ok_text="Create")
        self.name = self._row("Group name")
        self.sam = self._row("Group sAMAccountName")
        self.gtype = self._combo_row("Group type", list(GROUP_TYPES),
                                     "Global security")
        self.description = self._row("Description")
        self.ou = self._row("Organizational Unit (DN)", ou_dn, width=40)
        self._finish_buttons()

    def validate(self):
        return _need(self.name, "Group name") is not None \
            and _need(self.sam, "Group sAMAccountName") is not None \
            and _need(self.ou, "Organizational Unit") is not None

    def collect(self):
        return {"name": self.name.get().strip(),
                "sam": self.sam.get().strip(),
                "group_type": self.gtype.get().strip(),
                "description": self.description.get().strip(),
                "ou": self.ou.get().strip()}


class ResetPasswordDialog(DialogBase):
    def __init__(self, parent, target_name):
        super().__init__(parent, "Reset Password — {}".format(target_name),
                         ok_text="Reset Password")
        self.password = self._row("New password", show="*")
        self.confirm = self._row("Confirm password", show="*")
        self.must_change = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.body, text="User must change password at next logon",
                        variable=self.must_change).pack(anchor=tk.W, pady=4)
        self._finish_buttons()

    def validate(self):
        if not self.password.get():
            messagebox.showwarning("Missing value", "New password is required.",
                                   parent=self)
            return False
        if self.password.get() != self.confirm.get():
            messagebox.showwarning("Password mismatch",
                                   "The two passwords do not match.", parent=self)
            return False
        return True

    def collect(self):
        return {"password": self.password.get(),
                "must_change": self.must_change.get()}


class AddToGroupDialog(DialogBase):
    """Search for a group, pick one, and add the selected object to it."""

    def __init__(self, parent, search_fn):
        super().__init__(parent, "Add to Group", ok_text="Add to Group")
        self._search_fn = search_fn
        self._groups = []
        frame = ttk.Frame(self.body)
        frame.pack(fill=tk.X, pady=3)
        ttk.Label(frame, text="Group name", width=18, anchor=tk.W).pack(side=tk.LEFT)
        self.query = ttk.Entry(frame, width=30)
        self.query.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Search", command=self._do_search).pack(side=tk.LEFT, padx=4)
        self.listbox = tk.Listbox(self.body, height=10, width=55)
        self.listbox.pack(fill=tk.BOTH, expand=True, pady=4)
        self.listbox.bind("<Double-Button-1>", lambda _e: self._on_ok())
        self._finish_buttons()

    def _do_search(self):
        query = self.query.get().strip()
        if not query:
            messagebox.showinfo("Search", "Type part of a group name first.",
                                parent=self)
            return
        try:
            self._groups = self._search_fn(query)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            messagebox.showerror("Search failed", str(exc), parent=self)
            return
        self.listbox.delete(0, tk.END)
        for group in self._groups:
            self.listbox.insert(tk.END, "{} ({})".format(group["name"], group["sam"]))
        if not self._groups:
            self.listbox.insert(tk.END, "(no groups found)")

    def validate(self):
        sel = self.listbox.curselection()
        if not sel or not self._groups or sel[0] >= len(self._groups):
            messagebox.showwarning("No group selected",
                                   "Search for a group and select one first.",
                                   parent=self)
            return False
        return True

    def collect(self):
        return self._groups[self.listbox.curselection()[0]]


# --------------------------------------------------------------------------
# AD object properties
# --------------------------------------------------------------------------

def _attr_display_text(attr, values, binary, readonly=False):
    """Display text for one Attribute Editor row."""
    if values is None:
        text = "(cleared — will be deleted on Save)"
    elif not values:
        text = "(no value)"
    else:
        text = "; ".join(values)
    if binary:
        text = "(binary, read-only) " + text
    elif readonly:
        text = "(read-only) " + text
    return text


def _fill_attr_tree(tree, values, binary, needle="", readonly=()):
    """Fill an Attribute Editor tree from ``values`` ({attr: [str]}).

    ``needle`` filters rows client-side by case-insensitive substring
    match against the attribute name or its displayed value; an empty
    needle shows every attribute. Filtering only changes which rows
    are displayed — ``values`` (the working copy) is untouched, so
    pending edits survive filtering and clearing the search.
    Rows keep ``iid=attr`` so Edit/Clear always act on the right
    attribute even while filtered. Attributes in ``readonly`` are
    shown read-only (the caller refuses to edit them).
    """
    tree.delete(*tree.get_children())
    needle = (needle or "").strip().lower()
    readonly = set(readonly)
    for attr in sorted(values):
        text = _attr_display_text(attr, values.get(attr),
                                  binary.get(attr), attr in readonly)
        if needle and needle not in attr.lower() \
                and needle not in text.lower():
            continue
        tree.insert("", tk.END, iid=attr, values=(attr, text))


def _make_attr_search_row(parent, on_change):
    """A 'Search:' label + entry on its own row above an attribute list.

    Returns (StringVar holding the search text, clear button).
    Typing filters the list below it (client-side only); clearing
    the box shows every attribute again. The clear (×) button
    empties the search text and re-runs the filter, restoring the
    full list. It is always visible — simpler and more reliable in
    Tkinter than showing it only when text is present.
    """
    frame = ttk.Frame(parent)
    frame.pack(fill=tk.X, pady=(0, 4))
    ttk.Label(frame, text="Search:").pack(side=tk.LEFT)
    var = tk.StringVar()
    entry = ttk.Entry(frame, textvariable=var, width=32)
    entry.pack(side=tk.LEFT, padx=4, fill=tk.X, expand=True)
    entry.bind("<KeyRelease>", lambda _e: on_change())

    def _clear():
        var.set("")
        on_change()

    clear_btn = ttk.Button(frame, text="×", width=2, command=_clear)
    clear_btn.pack(side=tk.LEFT, padx=(0, 4))
    return var, clear_btn


def _edit_attribute_value(parent, attr, values):
    """Popup to edit one attribute's values (one value per line).

    Returns (True, new_values) on OK — new_values is None to clear
    the attribute — and (False, None) when the user cancels.
    """
    popup = tk.Toplevel(parent)
    popup.title("Edit — {}".format(attr))
    popup.transient(parent)
    body = ttk.Frame(popup, padding=12)
    body.pack(fill=tk.BOTH, expand=True)
    ttk.Label(body,
              text="One value per line. Leave empty to clear the attribute."
              ).pack(anchor=tk.W)
    text = tk.Text(body, width=60, height=8, wrap=tk.NONE)
    text.pack(fill=tk.BOTH, expand=True, pady=4)
    text.insert("1.0", "\n".join(values or []))
    result = {}

    def on_ok():
        lines = [line.strip()
                 for line in text.get("1.0", tk.END).splitlines()]
        lines = [line for line in lines if line]
        result["values"] = lines if lines else None
        popup.destroy()

    def on_clear():
        result["values"] = None
        popup.destroy()

    btns = ttk.Frame(body)
    btns.pack(fill=tk.X, pady=4)
    ttk.Button(btns, text="Clear attribute",
               command=on_clear).pack(side=tk.LEFT)
    ttk.Button(btns, text="Cancel",
               command=popup.destroy).pack(side=tk.RIGHT)
    ttk.Button(btns, text="OK",
               command=on_ok).pack(side=tk.RIGHT, padx=(0, 6))
    popup.grab_set()
    _center(popup, parent)
    popup.wait_window()
    if "values" not in result:
        return False, None
    return True, result["values"]


def _run_attribute_edit(dialog, attr):
    """Shared Edit flow for one Attribute Editor row.

    Refuses binary attributes, opens the edit popup, and on a change
    stores the new values, refills the tree and syncs the General-tab
    entry. Returns True when the value changed.
    """
    if dialog._binary.get(attr):
        messagebox.showinfo(
            "Read-only attribute",
            "'{}' is a binary attribute and cannot be edited.".format(attr),
            parent=dialog)
        return False
    changed, new_values = _edit_attribute_value(
        dialog, attr, dialog._values.get(attr) or [])
    if not changed:
        return False
    dialog._values[attr] = new_values
    dialog._fill_attr_tree()
    dialog._sync_general_entry(attr)
    return True


class UserPropertiesDialog(tk.Toplevel):
    """View/edit a user's AD attributes (General + Attribute Editor).

    ``attributes`` is the dict from ADClient.get_object_attributes:
    ``{attr: {"values": [str, ...], "binary": bool}}``. ``result`` is a
    dict ``{attr: new_value_or_list_or_None}`` of CHANGED attributes
    only (None = clear the attribute), or None when cancelled. The
    caller writes it back with ADClient.modify_object.
    """

    # (attribute, label) rows on the General tab. sAMAccountName is
    # shown read-only: renaming an account is risky and belongs in a
    # dedicated rename flow.
    GENERAL_FIELDS = (
        ("displayName", "Display name"),
        ("givenName", "First name"),
        ("sn", "Last name"),
        ("sAMAccountName", "Username (sAMAccountName)"),
        ("mail", "Email"),
        ("telephoneNumber", "Telephone"),
        ("title", "Title"),
        ("department", "Department"),
        ("company", "Company"),
        ("description", "Description"),
        ("physicalDeliveryOfficeName", "Office"),
    )

    def __init__(self, parent, display_name, attributes):
        super().__init__(parent)
        self.title("Properties — {}".format(display_name))
        self.transient(parent)
        self.result = None
        self._original = attributes
        # Working copy: {attr: [values] or None}. Binary flags are kept
        # separately; binary attributes are read-only in the UI.
        self._values = {attr: list(info["values"])
                        for attr, info in attributes.items()}
        self._binary = {attr: info["binary"]
                        for attr, info in attributes.items()}

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(12, 0))

        self._general_entries = {}
        general = ttk.Frame(notebook, padding=8)
        notebook.add(general, text="General")
        for attr, label in self.GENERAL_FIELDS:
            frame = ttk.Frame(general)
            frame.pack(fill=tk.X, pady=3)
            ttk.Label(frame, text=label, width=24, anchor=tk.W).pack(side=tk.LEFT)
            entry = ttk.Entry(frame, width=42)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            values = self._values.get(attr) or []
            if values:
                entry.insert(0, values[0])
            if attr == "sAMAccountName":
                entry.config(state=tk.DISABLED)
            self._general_entries[attr] = entry

        # Lockout state is read-only display, not an editable field:
        # lockoutTime is a system attribute AD manages itself (a
        # non-zero value means currently locked out; AD clears it to 0
        # when the lockout expires). It is deliberately NOT in
        # _general_entries, so Save never writes it back.
        lock_frame = ttk.Frame(general)
        lock_frame.pack(fill=tk.X, pady=3)
        ttk.Label(lock_frame, text="Locked out", width=24,
                  anchor=tk.W).pack(side=tk.LEFT)
        self._lockout_entry = ttk.Entry(lock_frame, width=42)
        self._lockout_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._lockout_entry.insert(
            0, "Yes" if is_locked_out(attributes) else "No")
        self._lockout_entry.config(state=tk.DISABLED)

        editor = ttk.Frame(notebook, padding=8)
        notebook.add(editor, text="Attribute Editor")
        ttk.Label(editor,
                  text="All attributes. Double-click (or Edit) to change a value; "
                       "binary attributes are read-only.",
                  font=("TkDefaultFont", 9, "italic")).pack(anchor=tk.W, pady=(0, 4))
        # Search sits on its own row above the attribute list; typing
        # filters the displayed attributes by name or value.
        self._attr_search_var, self._attr_clear_btn = _make_attr_search_row(
            editor, self._fill_attr_tree)
        cols = ("Attribute", "Value")
        self._attr_tree = ttk.Treeview(editor, columns=cols, show="headings",
                                       height=16)
        self._attr_tree.heading("Attribute", text="Attribute")
        self._attr_tree.heading("Value", text="Value")
        self._attr_tree.column("Attribute", width=200)
        self._attr_tree.column("Value", width=360)
        self._attr_tree.pack(fill=tk.BOTH, expand=True)
        self._attr_tree.bind("<Double-Button-1>", self._on_attr_double_click)
        self._fill_attr_tree()
        ttk.Button(editor, text="Edit…",
                   command=self._on_edit_attr).pack(anchor=tk.W, pady=(6, 0))

        buttons = ttk.Frame(self, padding=(12, 8, 12, 12))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Cancel",
                   command=self._on_cancel).pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Save",
                   command=self._on_save).pack(side=tk.RIGHT, padx=(0, 6))
        self.bind("<Escape>", lambda _e: self._on_cancel())
        self.minsize(620, 500)
        self.grab_set()
        _center(self, parent)

    # -- attribute editor ------------------------------------------------

    def _fill_attr_tree(self):
        # Filtering only changes which rows are shown; self._values
        # (the working copy, including pending edits) is untouched.
        _fill_attr_tree(self._attr_tree, self._values, self._binary,
                        self._attr_search_var.get())

    def _on_attr_double_click(self, _event):
        self._on_edit_attr()

    def _on_edit_attr(self):
        sel = self._attr_tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select an attribute first.", parent=self)
            return
        self._edit_attribute(sel[0])

    def _edit_attribute(self, attr):
        _run_attribute_edit(self, attr)

    def _sync_general_entry(self, attr):
        """Keep a General-tab field in step with an Attribute Editor edit."""
        entry = self._general_entries.get(attr)
        if entry is None:
            return
        values = self._values.get(attr) or []
        entry.config(state=tk.NORMAL)
        entry.delete(0, tk.END)
        if values:
            entry.insert(0, values[0])
        if attr == "sAMAccountName":
            entry.config(state=tk.DISABLED)

    # -- save / cancel ----------------------------------------------------

    def _on_save(self):
        # Pull the General tab into the working values. These
        # attributes are single-valued in AD; if one somehow had extra
        # values, keep them after the edited first value rather than
        # dropping them.
        for attr, entry in self._general_entries.items():
            if attr == "sAMAccountName":
                continue
            text = entry.get().strip()
            orig = self._original.get(attr, {"values": []})["values"]
            if not text:
                self._values[attr] = None
            elif len(orig) > 1:
                self._values[attr] = [text] + list(orig[1:])
            else:
                self._values[attr] = [text]
        changes = {}
        for attr, new_values in self._values.items():
            orig = list(self._original.get(attr, {"values": []})["values"] or [])
            if new_values is None or new_values == []:
                if orig:
                    changes[attr] = None
            elif list(new_values) != orig:
                changes[attr] = list(new_values)
        self.result = changes
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


class MemberPickerDialog(DialogBase):
    """Search for a user or group and pick one to add as a member."""

    def __init__(self, parent, search_fn):
        super().__init__(parent, "Add Member", ok_text="Add")
        self._search_fn = search_fn
        self._results = []
        frame = ttk.Frame(self.body)
        frame.pack(fill=tk.X, pady=3)
        ttk.Label(frame, text="Name", width=18, anchor=tk.W).pack(side=tk.LEFT)
        self.query = ttk.Entry(frame, width=30)
        self.query.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(frame, text="Search", command=self._do_search).pack(side=tk.LEFT, padx=4)
        self.listbox = tk.Listbox(self.body, height=10, width=55)
        self.listbox.pack(fill=tk.BOTH, expand=True, pady=4)
        self.listbox.bind("<Double-Button-1>", lambda _e: self._on_ok())
        self._finish_buttons()

    def _do_search(self):
        query = self.query.get().strip()
        if not query:
            messagebox.showinfo("Search", "Type part of a name first.",
                                parent=self)
            return
        try:
            self._results = self._search_fn(query)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            messagebox.showerror("Search failed", str(exc), parent=self)
            return
        self.listbox.delete(0, tk.END)
        for entry in self._results:
            label = "{} ({})".format(entry["name"],
                                     entry.get("sam") or "")
            if entry.get("type"):
                label += " — {}".format(entry["type"].capitalize())
            self.listbox.insert(tk.END, label)
        if not self._results:
            self.listbox.insert(tk.END, "(no users or groups found)")

    def validate(self):
        sel = self.listbox.curselection()
        if not sel or not self._results or sel[0] >= len(self._results):
            messagebox.showwarning("No member selected",
                                   "Search for a user or group and select "
                                   "one first.", parent=self)
            return False
        return True

    def collect(self):
        return self._results[self.listbox.curselection()[0]]


_GROUP_TYPE_LABELS = {value: label for label, value in GROUP_TYPES.items()}


class GroupPropertiesDialog(tk.Toplevel):
    """View/edit a group's attributes and manage its members.

    ``attributes`` is the dict from ADClient.get_object_attributes.
    ``client`` is the ADClient; ``base_dn`` is the domain DN used to
    search for members to add. ``members`` is the list of resolved
    member dicts (ADClient.resolve_members) in member order.
    ``result`` is a dict of CHANGED attributes only (None = clear),
    or None when cancelled — the ``member`` attribute is never in it,
    because membership is managed on the Members tab and applied
    immediately via add/remove_group_member. ``membership_changes``
    lists the membership changes applied during this dialog as
    [("added"/"removed", display_label)] so the caller can confirm
    them in the main window status bar.
    """

    # (attribute, label) rows on the General tab.
    GENERAL_FIELDS = (
        ("displayName", "Display name"),
        ("description", "Description"),
        ("mail", "Email"),
    )

    # Attributes shown read-only in the Attribute Editor: membership
    # is managed on the Members tab, applied immediately.
    READONLY_ATTRS = ("member",)

    def __init__(self, parent, display_name, attributes, client, base_dn,
                 group_dn, members):
        super().__init__(parent)
        self.title("Properties — {}".format(display_name))
        self.transient(parent)
        self.result = None
        self.membership_changes = []
        self._client = client
        self._base_dn = base_dn
        self._group_dn = group_dn
        self._original = attributes
        # Working copy: {attr: [values] or None}. Binary flags are kept
        # separately; binary attributes are read-only in the UI.
        self._values = {attr: list(info["values"])
                        for attr, info in attributes.items()}
        self._binary = {attr: info["binary"]
                        for attr, info in attributes.items()}
        # Ordered member DNs (the working membership) and the resolved
        # display info for them.
        self._member_dns = list(self._values.get("member") or [])
        self._members = {info["dn"].lower(): info for info in (members or [])}

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=(12, 0))

        self._build_general_tab(notebook)
        self._build_members_tab(notebook)
        self._build_editor_tab(notebook)

        buttons = ttk.Frame(self, padding=(12, 8, 12, 12))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Cancel",
                   command=self._on_cancel).pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Save",
                   command=self._on_save).pack(side=tk.RIGHT, padx=(0, 6))
        self.bind("<Escape>", lambda _e: self._on_cancel())
        self.minsize(620, 500)
        self.grab_set()
        _center(self, parent)

    # -- General ---------------------------------------------------------

    def _build_general_tab(self, notebook):
        general = ttk.Frame(notebook, padding=8)
        notebook.add(general, text="General")
        self._general_entries = {}
        for attr, label in self.GENERAL_FIELDS:
            frame = ttk.Frame(general)
            frame.pack(fill=tk.X, pady=3)
            ttk.Label(frame, text=label, width=24, anchor=tk.W).pack(side=tk.LEFT)
            entry = ttk.Entry(frame, width=42)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            values = self._values.get(attr) or []
            if values:
                entry.insert(0, values[0])
            self._general_entries[attr] = entry
        sam = (self._values.get("sAMAccountName") or [""])[0]
        self._readonly_row(general, "Username (sAMAccountName)", sam)
        self._readonly_row(general, "Group type", self._group_type_label())
        dn = (self._values.get("distinguishedName") or [self._group_dn])[0]
        self._readonly_row(general, "Distinguished name", dn)

    @staticmethod
    def _readonly_row(parent, label, value):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=3)
        ttk.Label(frame, text=label, width=24, anchor=tk.W).pack(side=tk.LEFT)
        entry = ttk.Entry(frame, width=42)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        entry.insert(0, value or "")
        entry.config(state=tk.DISABLED)

    def _group_type_label(self):
        values = self._values.get("groupType") or []
        if not values:
            return ""
        try:
            code = int(values[0])
        except (TypeError, ValueError):
            return str(values[0])
        return _GROUP_TYPE_LABELS.get(code, "Group type {}".format(code))

    # -- Members ----------------------------------------------------------

    def _build_members_tab(self, notebook):
        tab = ttk.Frame(notebook, padding=8)
        notebook.add(tab, text="Members")
        ttk.Label(tab,
                  text="Membership changes apply immediately.",
                  font=("TkDefaultFont", 9, "italic")).pack(anchor=tk.W, pady=(0, 4))
        cols = ("Name", "Username", "Type")
        self._member_tree = ttk.Treeview(tab, columns=cols, show="headings",
                                         height=12)
        for col in cols:
            self._member_tree.heading(col, text=col)
        self._member_tree.column("Name", width=220)
        self._member_tree.column("Username", width=150)
        self._member_tree.column("Type", width=90)
        self._member_tree.pack(fill=tk.BOTH, expand=True)
        self._fill_members()
        btns = ttk.Frame(tab)
        btns.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(btns, text="Add…",
                   command=self._on_add_member).pack(side=tk.LEFT)
        ttk.Button(btns, text="Remove",
                   command=self._on_remove_member).pack(side=tk.LEFT, padx=(6, 0))
        self._member_status = ttk.Label(tab, text="", wraplength=560)
        self._member_status.pack(anchor=tk.W, pady=(6, 0))

    def _fill_members(self):
        self._member_tree.delete(*self._member_tree.get_children())
        for dn in self._member_dns:
            info = self._members.get(dn.lower())
            if info is None:
                name, sam, kind = dn, "", ""
            else:
                name = info.get("display_name") or info.get("name") or dn
                sam = info.get("sam") or ""
                kind = (info.get("type") or "").capitalize()
            self._member_tree.insert("", tk.END, iid=dn,
                                     values=(name, sam, kind))

    def _on_add_member(self):
        def search(query):
            users = self._client.search_users(self._base_dn, query)
            groups = self._client.search_groups(self._base_dn, query)
            seen, out = set(), []
            for entry in users + groups:
                if entry["dn"].lower() not in seen:
                    seen.add(entry["dn"].lower())
                    out.append(entry)
            return out

        dlg = MemberPickerDialog(self, search)
        dlg.wait_window()
        if not dlg.result:
            return
        entry = dlg.result
        member_dn = entry["dn"]
        label = entry.get("display_name") or entry.get("name") or member_dn
        if member_dn.lower() in [d.lower() for d in self._member_dns]:
            messagebox.showinfo("Already a member",
                                "'{}' is already a member of this group.".format(label),
                                parent=self)
            return
        try:
            self._client.add_group_member(self._group_dn, member_dn)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            messagebox.showerror("Add member failed", str(exc), parent=self)
            return
        self._member_dns.append(member_dn)
        self._members[member_dn.lower()] = entry
        self._values["member"] = list(self._member_dns)
        self._fill_members()
        self._fill_attr_tree()
        self.membership_changes.append(("added", label))
        self._member_status.config(
            text="Added '{}' to the group.".format(label))

    def _on_remove_member(self):
        sel = self._member_tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select a member first.", parent=self)
            return
        dn = sel[0]
        info = self._members.get(dn.lower())
        label = (info.get("display_name") or info.get("name") or dn) \
            if info else dn
        if not messagebox.askyesno(
                "Remove member",
                "Remove '{}' from this group?".format(label), parent=self):
            return
        try:
            self._client.remove_group_member(self._group_dn, dn)
        except Exception as exc:  # noqa: BLE001 - shown to the user
            messagebox.showerror("Remove member failed", str(exc), parent=self)
            return
        self._member_dns = [d for d in self._member_dns
                            if d.lower() != dn.lower()]
        self._values["member"] = list(self._member_dns)
        self._fill_members()
        self._fill_attr_tree()
        self.membership_changes.append(("removed", label))
        self._member_status.config(
            text="Removed '{}' from the group.".format(label))

    # -- Attribute Editor -------------------------------------------------

    def _build_editor_tab(self, notebook):
        editor = ttk.Frame(notebook, padding=8)
        notebook.add(editor, text="Attribute Editor")
        ttk.Label(editor,
                  text="All attributes. Double-click (or Edit) to change a value; "
                       "binary attributes are read-only. Membership is managed "
                       "on the Members tab.",
                  font=("TkDefaultFont", 9, "italic")).pack(anchor=tk.W, pady=(0, 4))
        self._attr_search_var, self._attr_clear_btn = _make_attr_search_row(
            editor, self._fill_attr_tree)
        cols = ("Attribute", "Value")
        self._attr_tree = ttk.Treeview(editor, columns=cols, show="headings",
                                       height=16)
        self._attr_tree.heading("Attribute", text="Attribute")
        self._attr_tree.heading("Value", text="Value")
        self._attr_tree.column("Attribute", width=200)
        self._attr_tree.column("Value", width=360)
        self._attr_tree.pack(fill=tk.BOTH, expand=True)
        self._attr_tree.bind("<Double-Button-1>", self._on_attr_double_click)
        self._fill_attr_tree()
        ttk.Button(editor, text="Edit…",
                   command=self._on_edit_attr).pack(anchor=tk.W, pady=(6, 0))

    def _fill_attr_tree(self):
        _fill_attr_tree(self._attr_tree, self._values, self._binary,
                        self._attr_search_var.get(),
                        readonly=self.READONLY_ATTRS)

    def _on_attr_double_click(self, _event):
        self._on_edit_attr()

    def _on_edit_attr(self):
        sel = self._attr_tree.selection()
        if not sel:
            messagebox.showinfo("Nothing selected",
                                "Select an attribute first.", parent=self)
            return
        self._edit_attribute(sel[0])

    def _edit_attribute(self, attr):
        if attr in self.READONLY_ATTRS:
            messagebox.showinfo(
                "Read-only attribute",
                "'member' is managed on the Members tab and cannot be "
                "edited here.", parent=self)
            return
        _run_attribute_edit(self, attr)

    def _sync_general_entry(self, attr):
        """Keep a General-tab field in step with an Attribute Editor edit."""
        entry = self._general_entries.get(attr)
        if entry is None:
            return
        values = self._values.get(attr) or []
        entry.config(state=tk.NORMAL)
        entry.delete(0, tk.END)
        if values:
            entry.insert(0, values[0])

    # -- save / cancel ----------------------------------------------------

    def _on_save(self):
        # Pull the General tab into the working values. These
        # attributes are single-valued in AD; if one somehow had extra
        # values, keep them after the edited first value rather than
        # dropping them.
        for attr, entry in self._general_entries.items():
            text = entry.get().strip()
            orig = self._original.get(attr, {"values": []})["values"]
            if not text:
                self._values[attr] = None
            elif len(orig) > 1:
                self._values[attr] = [text] + list(orig[1:])
            else:
                self._values[attr] = [text]
        changes = {}
        for attr, new_values in self._values.items():
            # Membership is applied immediately on the Members tab and
            # is never written back as a whole-list REPLACE here.
            if attr == "member":
                continue
            orig = list(self._original.get(attr, {"values": []})["values"] or [])
            if new_values is None or new_values == []:
                if orig:
                    changes[attr] = None
            elif list(new_values) != orig:
                changes[attr] = list(new_values)
        self.result = changes
        self.destroy()

    def _on_cancel(self):
        self.result = None
        self.destroy()


# --------------------------------------------------------------------------
# DHCP / DNS
# --------------------------------------------------------------------------

class AddReservationDialog(DialogBase):
    def __init__(self, parent, scope_id):
        super().__init__(parent, "Add DHCP Reservation", ok_text="Add Reservation")
        ttk.Label(self.body, text="Scope: {}".format(scope_id)).pack(anchor=tk.W, pady=2)
        self.ip = self._row("IP address")
        self.mac = self._row("MAC address")
        self.name = self._row("Name")
        self.description = self._row("Description")
        self._finish_buttons()

    def validate(self):
        try:
            validate_ipv4(self.ip.get().strip())
        except ValueError as exc:
            messagebox.showwarning("Invalid IP address", str(exc), parent=self)
            return False
        try:
            normalize_mac(self.mac.get().strip())
        except ValueError as exc:
            messagebox.showwarning("Invalid MAC address", str(exc), parent=self)
            return False
        return _need(self.name, "Name") is not None

    def collect(self):
        return {"ip": self.ip.get().strip(),
                "mac": self.mac.get().strip(),
                "name": self.name.get().strip(),
                "description": self.description.get().strip()}


class EditReservationDialog(DialogBase):
    """Edit an existing DHCP reservation (same fields as Add).

    Pre-filled with the reservation's current values. Changing the
    IP address, Name or Description updates it in place; changing
    the MAC recreates the reservation (remove + re-add), because
    Set-DhcpServerv4Reservation identifies a reservation by its
    ClientId and cannot rename it.
    """

    def __init__(self, parent, scope_id, reservation):
        super().__init__(parent, "Edit DHCP Reservation",
                         ok_text="Save Reservation")
        ttk.Label(self.body, text="Scope: {}".format(scope_id)).pack(anchor=tk.W, pady=2)
        self.ip = self._row("IP address", reservation.get("IPAddress", ""))
        self.mac = self._row("MAC address", reservation.get("ClientId", ""))
        self.name = self._row("Name", reservation.get("Name", ""))
        self.description = self._row("Description",
                                     reservation.get("Description", ""))
        ttk.Label(self.body,
                  text="Note: changing the MAC address recreates the "
                       "reservation (remove + re-add).",
                  font=("TkDefaultFont", 9, "italic")).pack(anchor=tk.W, pady=(6, 0))
        self._finish_buttons()

    def validate(self):
        try:
            validate_ipv4(self.ip.get().strip())
        except ValueError as exc:
            messagebox.showwarning("Invalid IP address", str(exc), parent=self)
            return False
        try:
            normalize_mac(self.mac.get().strip())
        except ValueError as exc:
            messagebox.showwarning("Invalid MAC address", str(exc), parent=self)
            return False
        return _need(self.name, "Name") is not None

    def collect(self):
        return {"ip": self.ip.get().strip(),
                "mac": self.mac.get().strip(),
                "name": self.name.get().strip(),
                "description": self.description.get().strip()}


class AddRecordDialog(DialogBase):
    """Add a DNS record. The data field's label follows the record type."""

    def __init__(self, parent, zone_name):
        super().__init__(parent, "Add DNS Record", ok_text="Add Record")
        ttk.Label(self.body, text="Zone: {}".format(zone_name)).pack(anchor=tk.W, pady=2)
        self.rtype = self._combo_row("Record type", ["A", "CNAME", "PTR", "MX"], "A")
        self.rtype.bind("<<ComboboxSelected>>", lambda _e: self._update_labels())
        self.name = self._row("Record name (use @ for the zone apex)")
        self.data_label = ttk.Label(self.body, text="IPv4 address")
        self.data_label.pack(anchor=tk.W)
        self.data = ttk.Entry(self.body, width=40)
        self.data.pack(fill=tk.X, pady=2)
        self.pref_label = ttk.Label(self.body, text="Preference")
        self.preference = ttk.Entry(self.body, width=10)
        self.ttl = self._row("TTL in seconds (optional)")
        self._update_labels()
        self._finish_buttons()

    def _update_labels(self):
        rtype = self.rtype.get()
        labels = {"A": "IPv4 address", "CNAME": "Target hostname (alias)",
                  "PTR": "Target hostname (PTR domain name)",
                  "MX": "Mail exchange host"}
        self.data_label.config(text=labels.get(rtype, "Record data"))
        if rtype == "MX":
            self.pref_label.pack(anchor=tk.W)
            self.preference.pack(anchor=tk.W, pady=2)
        else:
            self.pref_label.pack_forget()
            self.preference.pack_forget()

    def validate(self):
        if _need(self.name, "Record name") is None:
            return False
        if _need(self.data, "Record data") is None:
            return False
        if self.rtype.get() == "A":
            try:
                validate_ipv4(self.data.get().strip())
            except ValueError as exc:
                messagebox.showwarning("Invalid IP address", str(exc), parent=self)
                return False
        if self.rtype.get() == "MX":
            try:
                int(self.preference.get().strip())
            except ValueError:
                messagebox.showwarning("Invalid preference",
                                       "MX preference must be a number.",
                                       parent=self)
                return False
        if self.ttl.get().strip():
            try:
                ttl_value = int(self.ttl.get().strip())
            except ValueError:
                messagebox.showwarning("Invalid TTL",
                                       "TTL must be a number of seconds.",
                                       parent=self)
                return False
            if ttl_value < 0:
                messagebox.showwarning("Invalid TTL",
                                       "TTL cannot be negative.",
                                       parent=self)
                return False
        return True

    def collect(self):
        ttl = self.ttl.get().strip()
        return {"type": self.rtype.get(),
                "name": self.name.get().strip(),
                "data": self.data.get().strip(),
                "preference": int(self.preference.get().strip() or 10),
                "ttl": int(ttl) if ttl else None}


class EditRecordDialog(DialogBase):
    """Edit an existing DNS record.

    The record name and type are the identity and are read-only;
    only the data and TTL change. For MX the data is the mail
    exchange host and the preference is a separate field. The
    record dict comes from DNSManager.list_records: ``Data`` is
    the display value (for MX "preference host") and
    ``RemoveData`` is the exact value identifying the record
    (for MX the host alone).
    """

    _DATA_LABELS = {
        "A": "IPv4 address",
        "AAAA": "IPv6 address",
        "CNAME": "Target hostname (alias)",
        "PTR": "Target hostname (PTR domain name)",
        "MX": "Mail exchange host",
        "TXT": "Text",
    }

    def __init__(self, parent, zone_name, record):
        super().__init__(parent, "Edit DNS Record", ok_text="Save Record")
        self._name = record.get("HostName", "")
        self._rtype = record.get("RecordType", "")
        ttk.Label(self.body, text="Zone: {}".format(zone_name)).pack(anchor=tk.W, pady=2)
        ttk.Label(self.body,
                  text="Record name: {}".format(self._name)).pack(anchor=tk.W, pady=2)
        ttk.Label(self.body,
                  text="Record type: {}".format(self._rtype)).pack(anchor=tk.W, pady=2)
        if self._rtype == "MX":
            data_value = record.get("RemoveData", "")
            pref_value = ""
            parts = (record.get("Data") or "").split(None, 1)
            if parts and parts[0].isdigit():
                pref_value = parts[0]
        else:
            data_value = record.get("Data", "")
            pref_value = ""
        self.data_label = ttk.Label(
            self.body, text=self._DATA_LABELS.get(self._rtype, "Record data"))
        self.data_label.pack(anchor=tk.W)
        self.data = ttk.Entry(self.body, width=40)
        self.data.pack(fill=tk.X, pady=2)
        self.data.insert(0, str(data_value))
        self.preference = None
        if self._rtype == "MX":
            self.pref_label = ttk.Label(self.body, text="Preference")
            self.pref_label.pack(anchor=tk.W)
            self.preference = ttk.Entry(self.body, width=10)
            self.preference.pack(anchor=tk.W, pady=2)
            self.preference.insert(0, pref_value)
        ttl = record.get("TTL")
        # The TTL arrives as seconds (a float from the JSON, e.g.
        # 3600.0). Guard against a missing, empty or non-numeric
        # value — int(float("")) raises ValueError, and a record
        # with no TTL must simply show an empty field.
        ttl_text = ""
        if ttl not in (None, ""):
            try:
                ttl_text = str(int(float(ttl)))
            except (TypeError, ValueError):
                ttl_text = ""
        self.ttl = self._row("TTL in seconds", ttl_text)
        self._finish_buttons()

    def validate(self):
        if _need(self.data, "Record data") is None:
            return False
        if self._rtype == "A":
            try:
                validate_ipv4(self.data.get().strip())
            except ValueError as exc:
                messagebox.showwarning("Invalid IP address", str(exc), parent=self)
                return False
        if self._rtype == "AAAA":
            try:
                validate_ipv6(self.data.get().strip())
            except ValueError as exc:
                messagebox.showwarning("Invalid IP address", str(exc), parent=self)
                return False
        if self._rtype == "MX":
            if self.preference is None or not self.preference.get().strip().isdigit():
                messagebox.showwarning("Invalid preference",
                                       "MX preference must be a number.",
                                       parent=self)
                return False
        if self.ttl.get().strip():
            try:
                ttl_value = int(self.ttl.get().strip())
            except ValueError:
                messagebox.showwarning("Invalid TTL",
                                       "TTL must be a number of seconds.",
                                       parent=self)
                return False
            if ttl_value < 0:
                messagebox.showwarning("Invalid TTL",
                                       "TTL cannot be negative.",
                                       parent=self)
                return False
        return True

    def collect(self):
        ttl = self.ttl.get().strip()
        pref = None
        if self._rtype == "MX" and self.preference is not None:
            pref = int(self.preference.get().strip())
        return {"type": self._rtype,
                "name": self._name,
                "data": self.data.get().strip(),
                "preference": pref,
                "ttl": int(ttl) if ttl else None}


# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------

class SettingsDialog(DialogBase):
    """User-defined connection defaults (domain, servers).

    Settings are saved to ``~/.msat/settings.json`` and used as
    the connection bar's defaults. They hold ONLY the domain and the
    servers list — credentials are NOT stored here, and the dialog
    says so plainly. ``current`` is the effective settings dict
    (already resolved against the generic placeholders).

    There is a single servers list. Role detection at connection time
    sorts out what each server does (DNS, DHCP, or both); there is no
    separate list per role.

    The servers list is a macOS-style list editor: a listbox with a
    text entry and + / − buttons beneath it. The default server is a
    dropdown whose options are exactly the servers in the list.
    Auto-default rules: one server in the list means that server is
    the default; several servers and no explicit pick means the first
    entry; an explicit pick is kept while it stays in the list, and
    removing it falls back to the first entry.
    """

    def __init__(self, parent, current):
        super().__init__(parent, "Settings", ok_text="Save")
        self.domain = self._row("Domain", current.get("domain", ""))
        # Source of truth for the list; the listbox is a view of it.
        self._servers = [s.strip() for s in current.get("servers", [])
                         if isinstance(s, str) and s.strip()]
        saved_default = (current.get("default_server") or "").strip()
        # The saved default counts as an explicit choice while it is
        # still in the list; otherwise the auto-default rules apply.
        self._explicit_default = saved_default in self._servers
        self._default = saved_default if self._explicit_default else ""
        self._build_servers_editor()
        self._build_default_row()
        ttk.Label(
            self.body,
            text="Credentials are NOT stored here — only the domain and\n"
                 "server defaults. Your username and password are\n"
                 "entered each time you connect and are never written\n"
                 "to disk.",
            font=("TkDefaultFont", 9, "italic")).pack(anchor=tk.W, pady=(8, 0))
        self._refresh_servers_ui()
        self._finish_buttons()

    def _build_servers_editor(self):
        """A macOS-style list editor: listbox + entry with + / −."""
        frame = ttk.Frame(self.body)
        frame.pack(fill=tk.X, pady=3)
        ttk.Label(frame, text="Servers", width=18, anchor=tk.W).pack(
            side=tk.LEFT, anchor=tk.N)
        right = ttk.Frame(frame)
        right.pack(side=tk.LEFT, fill=tk.X, expand=True)
        list_frame = ttk.Frame(right)
        list_frame.pack(fill=tk.X)
        self._servers_list = tk.Listbox(list_frame, height=4,
                                        exportselection=False)
        self._servers_list.pack(side=tk.LEFT, fill=tk.X, expand=True)
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL,
                               command=self._servers_list.yview)
        scroll.pack(side=tk.LEFT, fill=tk.Y)
        self._servers_list.config(yscrollcommand=scroll.set)
        self._servers_list.bind("<<ListboxSelect>>",
                                lambda _e: self._update_minus_state())
        entry_frame = ttk.Frame(right)
        entry_frame.pack(fill=tk.X, pady=(4, 0))
        self._new_entry = ttk.Entry(entry_frame, width=30)
        self._new_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._new_entry.bind("<Return>", self._on_new_entry_return)
        self._add_btn = ttk.Button(entry_frame, text="+", width=2,
                                   command=self._add_server)
        self._add_btn.pack(side=tk.LEFT, padx=(4, 0))
        self._minus_btn = ttk.Button(entry_frame, text="−", width=2,
                                     command=self._remove_server,
                                     state=tk.DISABLED)
        self._minus_btn.pack(side=tk.LEFT, padx=(4, 0))

    def _build_default_row(self):
        """Default server: a dropdown of the servers in the list."""
        frame = ttk.Frame(self.body)
        frame.pack(fill=tk.X, pady=3)
        ttk.Label(frame, text="Default server", width=18,
                  anchor=tk.W).pack(side=tk.LEFT)
        self.default_combo = ttk.Combobox(frame, width=38,
                                          state="readonly")
        self.default_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.default_combo.bind("<<ComboboxSelected>>",
                                self._on_default_selected)

    def _on_default_selected(self, _event):
        """The user explicitly picked a default from the dropdown."""
        value = self.default_combo.get()
        if value in self._servers:
            self._default = value
            self._explicit_default = True

    def _on_new_entry_return(self, _event):
        """Enter in the new-host entry adds the server (not Save)."""
        self._add_server()
        return "break"

    def _add_server(self):
        """Append the typed hostname; ignore empty input and dupes."""
        name = self._new_entry.get().strip()
        if not name:
            return
        if name in self._servers:
            # Silently skip a duplicate; select the existing row.
            index = self._servers.index(name)
            self._servers_list.selection_clear(0, tk.END)
            self._servers_list.selection_set(index)
            self._servers_list.see(index)
            self._new_entry.delete(0, tk.END)
            self._update_minus_state()
            return
        self._servers.append(name)
        self._new_entry.delete(0, tk.END)
        self._refresh_servers_ui()
        self._servers_list.selection_set(tk.END)
        self._servers_list.see(tk.END)
        self._update_minus_state()

    def _remove_server(self):
        """Remove the selected row; the default falls back if needed."""
        selection = self._servers_list.curselection()
        if not selection:
            return
        index = selection[0]
        self._servers.pop(index)
        self._refresh_servers_ui()
        if self._servers:
            self._servers_list.selection_set(
                min(index, len(self._servers) - 1))
            self._update_minus_state()

    def _refresh_servers_ui(self):
        """Rebuild the listbox and dropdown from the servers list."""
        self._servers_list.delete(0, tk.END)
        for server in self._servers:
            self._servers_list.insert(tk.END, server)
        self.default_combo.config(values=list(self._servers))
        self._apply_default_rules()
        self._update_minus_state()

    def _resolved_default(self):
        """The default server under the auto-default rules."""
        if not self._servers:
            return ""
        if self._explicit_default and self._default in self._servers:
            return self._default
        return self._servers[0]

    def _apply_default_rules(self):
        """Sync the dropdown to the resolved default server."""
        if self._explicit_default and self._default not in self._servers:
            self._explicit_default = False
        self._default = self._resolved_default()
        self.default_combo.set(self._default)

    def _update_minus_state(self):
        """− is enabled only when a row is selected."""
        state = (tk.NORMAL if self._servers_list.curselection()
                 else tk.DISABLED)
        self._minus_btn.config(state=state)

    def validate(self):
        if _need(self.domain, "Domain") is None:
            return False
        if not self._servers:
            messagebox.showwarning(
                "Missing value",
                "At least one server is required.",
                parent=self)
            self._new_entry.focus_set()
            return False
        return True

    def collect(self):
        return {
            "domain": self.domain.get().strip(),
            "servers": list(self._servers),
            "default_server": self._resolved_default(),
        }



# --------------------------------------------------------------------------
# Update
# --------------------------------------------------------------------------

# Brief install steps shown after a release zip is downloaded. MSAT
# never installs itself: a running .app cannot replace itself, and
# overwriting a running program's source files is fragile.
_INSTALL_STEPS = (
    "To install it:\n"
    "• From source — unzip the file over the project folder, re-run\n"
    "  ./setup.sh if needed, then relaunch.\n"
    "• MSAT.app — unzip and replace MSAT.app in /Applications.\n"
    "Your settings are not touched — they live in ~/.msat/settings.json,\n"
    "outside the app folder."
)


class UpdateDialog(tk.Toplevel):
    """A newer MSAT release is available (modal).

    Shows the new version against the running version, the release
    notes from GitHub (read-only, scrollable), and three actions:
    Download (fetch the release zip into ~/Downloads, then show the
    saved path and the install steps), View on GitHub (open the
    release page in the default browser), Later (dismiss).
    """

    def __init__(self, parent, release, current_version):
        super().__init__(parent)
        self.title("MSAT update available")
        self.transient(parent)
        self.release = release
        self.current_version = current_version

        body = ttk.Frame(self, padding=12)
        body.pack(fill=tk.BOTH, expand=True)

        self.title_label = ttk.Label(
            body,
            text="MSAT {} is available — you have v{}.".format(
                release["tag"], current_version),
            font=("", 11, "bold"), wraplength=460, justify=tk.LEFT)
        self.title_label.pack(fill=tk.X, pady=(0, 8))

        notes_frame = ttk.Frame(body)
        notes_frame.pack(fill=tk.BOTH, expand=True)
        self.notes_text = tk.Text(notes_frame, wrap=tk.WORD, width=62,
                                  height=14)
        scrollbar = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL,
                                  command=self.notes_text.yview)
        self.notes_text.configure(yscrollcommand=scrollbar.set)
        self.notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.notes_text.insert("1.0", release.get("body") or
                               "(No release notes.)")
        self.notes_text.config(state=tk.DISABLED)

        self.status_label = ttk.Label(body, text="", wraplength=460,
                                      justify=tk.LEFT)
        self.status_label.pack(fill=tk.X, pady=(8, 0))

        buttons = ttk.Frame(self, padding=(12, 0, 12, 12))
        buttons.pack(fill=tk.X)
        self.download_btn = ttk.Button(buttons, text="Download",
                                       command=self._on_download)
        self.download_btn.pack(side=tk.LEFT)
        ttk.Button(buttons, text="View on GitHub",
                   command=self._on_view).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(buttons, text="Later",
                   command=self.destroy).pack(side=tk.RIGHT)
        self.bind("<Escape>", lambda _e: self.destroy())
        self.grab_set()
        _center(self, self.master)

    def _on_download(self):
        """Fetch the release zip into ~/Downloads, then report where
        it landed and how to install it."""
        self.download_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Downloading…")
        self.update_idletasks()
        path = updater.download_release_zip(self.release.get("zip_url"))
        if path is None:
            if not self.release.get("zip_url"):
                self.status_label.config(
                    text="This release has no downloadable zip — "
                         "use View on GitHub to get it.")
            else:
                self.status_label.config(
                    text="Download failed — check your connection and "
                         "try again, or use View on GitHub.")
            self.download_btn.config(state=tk.NORMAL)
            return
        self.status_label.config(
            text="Downloaded to:\n{}\n\n{}".format(path, _INSTALL_STEPS))

    def _on_view(self):
        webbrowser.open(self.release.get("html_url") or "")
