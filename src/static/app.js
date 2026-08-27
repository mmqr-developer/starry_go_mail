// The only client-side script in the app, and deliberately tiny.
//
// Everything else renders on the server. That is a security position rather
// than a style preference: this page sits next to message bodies a stranger
// wrote, so the less script there is here, the less there is for a
// sanitiser bypass to reach.
//
// Two behaviours, both of which have no markup equivalent:
(function () {
  'use strict';

  // 1. Close the account switcher when you click away from it.
  //
  // The menu is a native <details>, so opening, closing, keyboard operation
  // and screen-reader announcement all work without this. Only
  // close-on-outside-click is missing, and a menu that stays open when you
  // click elsewhere feels broken. With JavaScript unavailable the menu still
  // works; it just needs a second click on the summary to close.
  // The selector is `details.menu`, which is the switcher and every toolbar
  // dropdown: they are all the same native element and want the same one
  // behaviour, so a new menu gets it by carrying the class rather than by
  // somebody remembering to add it here.
  document.addEventListener('click', function (evt) {
    document.querySelectorAll('details.menu[open]').forEach(function (d) {
      if (!d.contains(evt.target)) d.removeAttribute('open');
    });
  });

  document.addEventListener('keydown', function (evt) {
    if (evt.key !== 'Escape') return;
    var open = document.querySelector('details.menu[open]');
    if (!open) return;
    open.removeAttribute('open');
    var summary = open.querySelector('summary');
    if (summary) summary.focus();
  });

  // 2. Confirm the destructive actions.
  //
  // On submit rather than on the button's click, so it also catches Enter
  // pressed in the form -- a click handler alone is bypassed by the keyboard,
  // which is exactly the path someone using a screen reader takes.
  document.addEventListener('submit', function (evt) {
    var form = evt.target;
    if (!form || !form.dataset || !form.dataset.confirm) return;
    if (!window.confirm(form.dataset.confirm)) {
      evt.preventDefault();
    }
  }, true);

  // 3. A Show/Hide control on every password field.
  //
  // Built here rather than in the templates, for two reasons. Without
  // scripting the button could not work, and a dead control is worse than no
  // control -- so with JavaScript off nothing appears and the field is an
  // ordinary password box. And every password field in the app gets one
  // automatically, including any added later: a template-by-template version
  // is a list that goes out of date silently, which is exactly how the field
  // people most need to check ends up being the one without a button.
  //
  // Why it is worth having at all: several of these fields hold a password
  // the user is copying from somewhere else -- a mailbox password issued by
  // an administrator, pasted or typed from a phone -- and there is no
  // "forgot it" path for a mailbox password stored here. A typo silently
  // becomes an IMAP login failure attributed to the server.
  function labelTextFor(input) {
    var lab = input.id && document.querySelector('label[for="' + input.id + '"]');
    if (!lab) return 'password';
    // The label may carry a hint span ("(blank = the address)"); the
    // accessible name of the button should be the field, not the aside.
    var clone = lab.cloneNode(true);
    clone.querySelectorAll('.hint').forEach(function (h) { h.remove(); });
    // Case is left alone: lowercasing would turn "SMTP password" into
    // "smtp password", which some screen readers then read as a word.
    return (clone.textContent || '').trim() || 'password';
  }

  function addToggle(input) {
    if (input.dataset.pwToggle) return;
    input.dataset.pwToggle = '1';

    var wrap = document.createElement('div');
    wrap.className = 'pw-wrap';
    input.parentNode.insertBefore(wrap, input);
    wrap.appendChild(input);

    var name = labelTextFor(input);
    var btn = document.createElement('button');
    // type=button, or it submits the form it sits in.
    btn.type = 'button';
    btn.className = 'pw-toggle';
    btn.textContent = 'Show';
    // The visible word is the same on every button on the page, so the
    // accessible name names the field too -- "Show new password" against
    // "Show confirm new password". aria-pressed is deliberately not used:
    // a toggle button announced as "Show password, pressed" leaves the
    // listener to work out which state that is, while a label that changes
    // to "Hide" simply says what the next press does.
    btn.setAttribute('aria-label', 'Show ' + name);
    btn.addEventListener('click', function () {
      var reveal = input.type === 'password';
      input.type = reveal ? 'text' : 'password';
      btn.textContent = reveal ? 'Hide' : 'Show';
      btn.setAttribute('aria-label', (reveal ? 'Hide ' : 'Show ') + name);
      // Focus returns to the field with the caret at the end, so revealing
      // mid-entry does not cost the typing position.
      var at = input.value.length;
      input.focus();
      try { input.setSelectionRange(at, at); } catch (e) { /* number-ish inputs */ }
    });
    wrap.appendChild(btn);
  }

  function addToggles(root) {
    (root || document).querySelectorAll('input[type=password]').forEach(addToggle);
  }

  addToggles(document);
  // htmx swaps whole panes, so newly arrived fields need the same treatment.
  document.body.addEventListener('htmx:load', function (evt) {
    addToggles(evt.target);
  });

  // 4. Select-all used to live here, ticking every .msg-check by hand.
  //
  // It is a server verb now (POST /app/list/select/all): the selection is the
  // server's, so the honest way to tick everything is to say so and be sent
  // back a list drawn from the new record. That also fixed what this could not
  // do -- a box ticked here was lost the next time the list re-rendered, which
  // is on every action and every arrival, because nothing but the browser knew
  // about it.

  // 5. Print the open message.
  //
  // window.print() on the whole reader page rather than on the iframe: the
  // message body is sandboxed with no same-origin access, so its own print()
  // is not reachable from here -- and by design. A print stylesheet hides the
  // chrome, and the browser renders the framed document as part of the page.
  document.addEventListener('click', function (evt) {
    var btn = evt.target.closest && evt.target.closest('[data-print]');
    if (!btn) return;
    evt.preventDefault();
    var open = btn.closest('details.menu');
    if (open) open.removeAttribute('open');
    window.print();
  });

  // 6. The composer: the format switch, and the rich editor.
  //
  // This is the one substantial piece of script in the app, and it is here
  // rather than on the server because there is no server-side version of
  // "make the selected words bold".
  //
  // It is built on document.execCommand, which is formally deprecated and has
  // no replacement. The alternatives are a large third-party editor -- which
  // this app cannot take, being a single binary with no external requests and
  // a CSP that forbids them -- or hand-written Range and Selection surgery,
  // which is a great deal of code that gets the hard cases wrong. execCommand
  // is implemented in every current browser and is not going anywhere while
  // every webmail client in existence depends on it. The deprecation is worth
  // knowing about; it is not worth paying either alternative price for today.
  //
  // **Nothing here is a security control.** The toolbar decides what is
  // convenient to type, not what is allowed to be sent: the editor's markup
  // travels in an ordinary form field, so it is sanitised on the server by
  // composePolicy in sanitize.go. If this file were deleted the app would
  // still be safe -- it would just be plain text only.
  function initComposer(form) {
    if (!form || form.dataset.composerReady) return;
    var surface = form.querySelector('[data-rte-surface]');
    var rich = form.querySelector('[data-rich-editor]');
    var plain = form.querySelector('[data-body-plain]');
    var textarea = form.querySelector('textarea[name=body]');
    var hidden = form.querySelector('input[name=html_body]');
    var radios = form.querySelectorAll('input[name=format]');
    if (!surface || !rich || !plain || !textarea || !hidden) return;
    form.dataset.composerReady = '1';

    // The editor block ships hidden so that with scripting off it never
    // appears -- a toolbar of buttons that do nothing is worse than no
    // toolbar. Reaching this line is the proof that script runs.
    rich.hidden = false;

    // -- the selection ------------------------------------------------------
    // Every toolbar control has to act on the selection that was in the
    // editor, but using one moves focus out of it: a colour input opens the
    // native picker, and the link field has to be typed into. The last
    // in-editor range is therefore tracked continuously and restored before
    // any command runs.
    var savedRange = null;
    document.addEventListener('selectionchange', function () {
      // htmx replaces the whole pane, so a composer left behind by an earlier
      // navigation still has this listener bound. Its surface is detached, and
      // contains() below would be false anyway -- this just says so plainly
      // rather than leaving it to be inferred.
      if (!surface.isConnected) return;
      var sel = window.getSelection();
      if (!sel || !sel.rangeCount) return;
      var node = sel.getRangeAt(0).commonAncestorContainer;
      if (surface.contains(node.nodeType === 1 ? node : node.parentNode)) {
        savedRange = sel.getRangeAt(0).cloneRange();
        refreshState();
      }
    });

    function restoreSelection() {
      surface.focus();
      if (!savedRange) return;
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(savedRange);
    }

    // -- running a command --------------------------------------------------
    function exec(cmd, value) {
      restoreSelection();
      try {
        // The value argument is omitted rather than passed as null, because
        // some commands use it for something. insertHorizontalRule takes it as
        // the id of the element it inserts, so passing null produced
        // `<hr id="null">` -- and a second rule produced a duplicate id.
        if (value === undefined) document.execCommand(cmd, false);
        else document.execCommand(cmd, false, value);
      } catch (e) { /* an unsupported command is a no-op, not a failure */ }
      sync();
      refreshState();
    }

    // sync copies the editor into the field that actually submits.
    // contenteditable is not a form control and posts nothing by itself.
    function sync() { hidden.value = surface.innerHTML; }

    // -- toolbar ------------------------------------------------------------
    var toolbar = form.querySelector('[data-rte-toolbar]');

    // Both of these match `.rte-btn[data-cmd]`, **not** `.rte-btn**, and the
    // attribute is doing real work rather than being tidier.
    //
    // Not every control in this toolbar is an execCommand button. Insert image
    // is a <label> wrapping a file input, and the image-width buttons have
    // their own handler. Matching on the class alone caught those too and
    // called preventDefault on them -- which for a label cancels the one thing
    // a label does, so Insert image opened no file chooser and did nothing at
    // all. Then it ran exec(undefined) for good measure.
    //
    // mousedown, not click, for the focus half: preventing the default there
    // stops the button taking focus, which is what stops the selection
    // collapsing before the command can act on it.
    toolbar.addEventListener('mousedown', function (evt) {
      if (evt.target.closest('.rte-btn[data-cmd]')) evt.preventDefault();
    });

    toolbar.addEventListener('click', function (evt) {
      var btn = evt.target.closest('.rte-btn[data-cmd]');
      if (!btn) return;
      evt.preventDefault();
      var cmd = btn.dataset.cmd;
      if (cmd === 'createLink') { openLinkBar(); return; }
      exec(cmd);
    });

    toolbar.addEventListener('change', function (evt) {
      var el = evt.target;
      if (!el.dataset || !el.dataset.cmd) return;
      if (el.dataset.cmd === 'formatBlock') {
        // Angle brackets around the tag: current browsers accept the bare
        // name, older ones only the wrapped form, and the wrapped form is
        // accepted everywhere.
        exec('formatBlock', '<' + el.value + '>');
        el.selectedIndex = 0;
        return;
      }
      exec(el.dataset.cmd, el.value);
    });

    // The pressed state of the toggles, so the toolbar reflects the caret.
    var stateful = ['bold', 'italic', 'underline', 'strikeThrough',
      'insertUnorderedList', 'insertOrderedList',
      'justifyLeft', 'justifyCenter', 'justifyRight'];
    function refreshState() {
      if (rich.hidden) return;
      stateful.forEach(function (cmd) {
        var btn = toolbar.querySelector('.rte-btn[data-cmd="' + cmd + '"]');
        if (!btn) return;
        var on = false;
        try { on = document.queryCommandState(cmd); } catch (e) { /* unsupported */ }
        btn.classList.toggle('is-on', on);
        btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
    }

    // -- the link bar -------------------------------------------------------
    var linkbar = form.querySelector('[data-rte-linkbar]');
    var urlField = form.querySelector('[data-rte-url]');

    function openLinkBar() {
      linkbar.hidden = false;
      // Offer the selected text when it already looks like an address, which
      // is the common case: paste a URL, select it, press the button.
      var sel = window.getSelection();
      var text = sel ? sel.toString().trim() : '';
      urlField.value = /^(https?:\/\/|mailto:)/i.test(text) ? text : '';
      urlField.focus();
    }
    function closeLinkBar() {
      linkbar.hidden = true;
      restoreSelection();
    }
    form.querySelector('[data-rte-link-apply]').addEventListener('click', function () {
      var url = urlField.value.trim();
      // Only the schemes the server will keep. Anything else -- javascript:
      // above all -- is refused here so the failure is visible in the editor
      // rather than silently stripped on send.
      if (!/^(https?:\/\/|mailto:)/i.test(url)) {
        urlField.setCustomValidity('Links must start with http://, https:// or mailto:');
        urlField.reportValidity();
        return;
      }
      urlField.setCustomValidity('');
      linkbar.hidden = true;
      exec('createLink', url);
    });
    form.querySelector('[data-rte-link-cancel]').addEventListener('click', closeLinkBar);
    urlField.addEventListener('input', function () { urlField.setCustomValidity(''); });
    urlField.addEventListener('keydown', function (evt) {
      // Enter inside the bar applies the link; without this it submits the
      // form, which sends the message.
      if (evt.key === 'Enter') {
        evt.preventDefault();
        form.querySelector('[data-rte-link-apply]').click();
      } else if (evt.key === 'Escape') {
        evt.preventDefault();
        closeLinkBar();
      }
    });

    // -- switching format ---------------------------------------------------
    // The content moves in the direction of the switch, always. The
    // alternative -- carrying it across only when the destination is empty --
    // leaves the other side holding a stale copy, and the user cannot see
    // which of the two the message will be sent from.
    function richHasFormatting() {
      return !!surface.querySelector(
        'b,strong,i,em,u,s,strike,a,ul,ol,h1,h2,h3,h4,h5,h6,' +
        'blockquote,pre,font,img,hr,table,[style]');
    }

    function applyFormat(fmt, moveContent) {
      var html = fmt === 'html';
      if (moveContent) {
        if (html) {
          // Escaping is the browser's job here: assigning to textContent and
          // reading innerHTML back is what makes a typed "<b>" arrive as the
          // characters someone typed rather than as a tag.
          var lines = textarea.value.split('\n').map(function (line) {
            var div = document.createElement('div');
            if (line === '') div.appendChild(document.createElement('br'));
            else div.textContent = line;
            return div.outerHTML;
          });
          surface.innerHTML = lines.join('');
        } else {
          // innerText rather than textContent: it respects the line breaks the
          // rendering actually shows, so a bulleted list becomes lines rather
          // than one run-on paragraph.
          //
          // The collapse matches collapseBlankLines in sanitize.go, which the
          // server applies to the plain alternative of every HTML message.
          // Without it a blank line gains a newline on each switch: a blank
          // line is <div><br></div>, and innerText counts both the <br> and
          // the block boundary, so a message toggled between the two formats a
          // few times drifts further apart every time.
          textarea.value = surface.innerText.replace(/\n{3,}/g, '\n\n');
        }
      }
      plain.hidden = html;
      rich.hidden = !html;
      if (!html) linkbar.hidden = true;
      sync();
      refreshState();
    }

    radios.forEach(function (radio) {
      radio.addEventListener('change', function () {
        if (!radio.checked) return;
        if (radio.value === 'plain' && richHasFormatting()) {
          if (!window.confirm(
              'Switching to plain text drops the formatting in this message. Continue?')) {
            form.querySelector('input[name=format][value=html]').checked = true;
            return;
          }
        }
        applyFormat(radio.value, true);
      });
    });

    // -- typing -------------------------------------------------------------
    surface.addEventListener('input', sync);

    // The shortcuts browsers already bind inside a contenteditable. Listed
    // only so the toolbar's pressed state keeps up with the keyboard; the
    // formatting itself is the browser's own doing.
    surface.addEventListener('keyup', refreshState);
    surface.addEventListener('mouseup', refreshState);

    // Paste as markup is the point of an HTML composer, so it is left alone --
    // the server sanitises it. Shift+Paste for plain text is the browser's.

    form.addEventListener('submit', sync);

    // -- images -------------------------------------------------------------
    // Uploaded to the server rather than turned into a data: URI here. Two
    // reasons, and the second is the one that matters: the browser cannot
    // rescale a 50MB photo without decoding all of it in the page, and a
    // data: URI in the editor would make every keystroke's worth of undo
    // history carry a copy of the picture. Keeping the pixels on the server
    // and referring to them by URL keeps the document small until the moment
    // the message is actually assembled.
    var imageInput = form.querySelector('[data-image-input]');
    var imageRow = form.querySelector('[data-image-row]');
    var imageNote = form.querySelector('[data-image-note]');
    var selectedImage = null;

    function note(msg, isError) {
      if (!imageNote) return;
      imageNote.textContent = msg || '';
      imageNote.classList.toggle('is-error', !!isError);
    }

    function uploadImage(file) {
      if (!file) return;
      if (!/^image\//.test(file.type)) {
        note('That is not an image.', true);
        return;
      }
      note('Adding image…');
      var body = new FormData();
      body.append('image', file);
      fetch('/app/compose/image', {
        method: 'POST', body: body, credentials: 'same-origin'
      }).then(function (res) {
        return res.json().then(function (data) { return {ok: res.ok, data: data}; });
      }).then(function (r) {
        if (!r.ok || !r.data || r.data.error) {
          note((r.data && r.data.error) || 'The image could not be added.', true);
          return;
        }
        insertImage(r.data);
        note('');
      }).catch(function () {
        note('The image could not be added.', true);
      });
    }

    function insertImage(data) {
      restoreSelection();
      var img = document.createElement('img');
      img.src = data.url;
      img.alt = '';
      // A width attribute as well as the pixels, so the message carries its
      // intended size rather than relying on the recipient's client to guess
      // from the file. It is what makes 50% still look like 50% over there.
      img.setAttribute('width', data.width);
      // execCommand('insertImage') exists and is not used: it takes a URL and
      // gives no way to set the other attributes, so the width would have to
      // be found and applied afterwards by searching for the img it just made.
      insertNodeAtCaret(img);
      sync();
    }

    function insertNodeAtCaret(node) {
      var sel = window.getSelection();
      if (!sel || !sel.rangeCount || !surface.contains(
          sel.getRangeAt(0).commonAncestorContainer.nodeType === 1
            ? sel.getRangeAt(0).commonAncestorContainer
            : sel.getRangeAt(0).commonAncestorContainer.parentNode)) {
        surface.appendChild(node);
        return;
      }
      var range = sel.getRangeAt(0);
      range.deleteContents();
      range.insertNode(node);
      // Caret after the image, so typing continues beside it rather than
      // before it.
      range.setStartAfter(node);
      range.collapse(true);
      sel.removeAllRanges();
      sel.addRange(range);
      savedRange = range.cloneRange();
    }

    if (imageInput) {
      imageInput.addEventListener('change', function () {
        uploadImage(imageInput.files && imageInput.files[0]);
        // Cleared so that choosing the same file twice in a row still fires.
        imageInput.value = '';
      });
    }

    // Pasting a picture copied from another program. The clipboard carries it
    // as a file, alongside whatever text representation the source offered --
    // so this looks for an image first and only then lets the normal paste
    // happen.
    surface.addEventListener('paste', function (evt) {
      var dt = evt.clipboardData;
      if (!dt) return;
      var file = null;
      for (var i = 0; i < dt.items.length; i++) {
        if (dt.items[i].kind === 'file' && /^image\//.test(dt.items[i].type)) {
          file = dt.items[i].getAsFile();
          break;
        }
      }
      if (!file) return;   // ordinary paste: markup, handled by the browser
      evt.preventDefault();
      uploadImage(file);
    });

    // -- the image size bar --------------------------------------------------
    function showImageRow(img) {
      selectedImage = img;
      // The outline is what makes "these buttons act on that picture" visible.
      // The browser's own selection highlight on an image inside a
      // contenteditable is easy to miss and disappears the moment focus moves
      // to the toolbar.
      surface.querySelectorAll('img.is-selected').forEach(function (el) {
        el.classList.remove('is-selected');
      });
      if (img) img.classList.add('is-selected');
      if (!imageRow) return;
      imageRow.hidden = !img;
      if (!img) { note(''); return; }
      var pct = currentPercent(img);
      imageRow.querySelectorAll('[data-image-size]').forEach(function (b) {
        var on = String(pct) === b.dataset.imageSize;
        b.classList.toggle('is-on', on);
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
      });
    }

    function currentPercent(img) {
      var m = /\/app\/compose\/image\/[^/]+\/(\d+)$/.exec(img.getAttribute('src') || '');
      return m ? parseInt(m[1], 10) : 0;
    }

    // Clicking a picture selects it. contenteditable already lets a click land
    // inside an image without selecting it as an object, so the selection is
    // set explicitly -- otherwise the size buttons would apply to whichever
    // image was last touched rather than the one that looks selected.
    surface.addEventListener('click', function (evt) {
      var img = evt.target.closest && evt.target.closest('img');
      if (img && surface.contains(img) && currentPercent(img)) {
        var range = document.createRange();
        range.selectNode(img);
        var sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        savedRange = range.cloneRange();
        showImageRow(img);
      } else {
        showImageRow(null);
      }
    });

    if (imageRow) {
      imageRow.addEventListener('click', function (evt) {
        var btn = evt.target.closest('[data-image-size]');
        if (!btn || !selectedImage) return;
        evt.preventDefault();
        var src = selectedImage.getAttribute('src') || '';
        var next = src.replace(/\/(\d+)$/, '/' + btn.dataset.imageSize);
        if (next === src) return;
        note('Resizing…');
        // Fetched before the src is swapped, so a size the server can no
        // longer produce does not leave a broken picture in the message. The
        // server builds the variant on this request and the <img> below then
        // takes it from the browser's cache rather than asking twice.
        fetch(next, {credentials: 'same-origin'}).then(function (res) {
          if (!res.ok) throw new Error('gone');
          var img = selectedImage;
          img.setAttribute('src', next);
          img.removeAttribute('width');
          // Synced now, not only in onload. The width below is a refinement;
          // the src is the message. Waiting for the load to sync means an
          // image that fails to render leaves the *old* URL in the field that
          // actually gets submitted.
          sync();
          img.onload = function () {
            img.setAttribute('width', img.naturalWidth);
            sync();
          };
          showImageRow(selectedImage);
          note('');
        }).catch(function () {
          note('That size is no longer available for this image.', true);
        });
      });
    }

    // -- attachments -------------------------------------------------------
    // The paperclip is htmx: the file input posts the chosen files together
    // with the ids already in the strip, and the server answers with the whole
    // strip. Removing a row is the same request in reverse. See attach.go and
    // the "attachStrip" template.
    //
    // All that is left here is revealing the control, which cannot be an
    // attribute: without script the input would post files nowhere, and a
    // paperclip that silently attaches nothing is worse than no paperclip.
    var attachControl = form.querySelector('[data-attach-control]');
    var attachInput = form.querySelector('[data-attach-input]');
    var attachList = form.querySelector('[data-attach-list]');
    if (attachControl) attachControl.hidden = false;

    // Cleared after htmx has sent it, so choosing the same file twice in a row
    // still fires a change event. This was hx-on::after-request until the CSP
    // was read properly: no 'unsafe-eval' means htmx cannot compile hx-on, so
    // the attribute never ran and the second choice did nothing.
    if (attachInput) {
      attachInput.addEventListener('htmx:afterRequest', function () {
        attachInput.value = '';
      });
    }

    // What the strip currently holds, for the dirty check below. Attaching a
    // file is an edit: without this, opening a reply, attaching a document and
    // navigating away would decide nothing had changed and save no draft.
    function attachSnapshot() {
      if (!attachList) return '';
      return Array.prototype.map.call(
        attachList.querySelectorAll('input[name=attach]'),
        function (el) { return el.value; }).join(',');
    }

    // -- drafting with Ollama ----------------------------------------------
    // The button is only in the markup when a server and model are configured,
    // so there is nothing here to check: if the element is absent this whole
    // block binds nothing.
    var assistBtn = form.querySelector('[data-assist]');
    var assistBar = form.querySelector('[data-assist-bar]');
    if (assistBtn && assistBar) {
      var assistPrompt = assistBar.querySelector('[data-assist-prompt]');
      var assistNote = assistBar.querySelector('[data-assist-note]');
      var assistLabel = assistBar.querySelector('[data-assist-label]');
      var assistGo = assistBar.querySelector('[data-assist-go]');
      // Three kinds, not two. A forward has a quoted message like a reply
      // does, but what it wants written is a covering note rather than an
      // answer -- writing a reply to a message you are passing on would be
      // addressing the wrong person.
      var assistKind = assistBtn.dataset.assistKind || 'new';
      var hasQuote = assistKind === 'reply' || assistKind === 'replyall' ||
                     assistKind === 'forward';

      function assistSay(msg, isError) {
        assistNote.textContent = msg || '';
        assistNote.classList.toggle('is-error', !!isError);
      }

      assistBtn.addEventListener('click', function () {
        assistBar.hidden = false;
        // Anything with a quoted message already has its subject matter, so
        // the box is an optional steer: "reply saying no, politely" is a
        // different message from whatever the model would pick on its own.
        if (assistKind === 'reply' || assistKind === 'replyall') {
          assistLabel.textContent = 'Anything the reply should say? (optional)';
          assistPrompt.placeholder = 'decline politely, suggest next week instead';
        } else if (assistKind === 'forward') {
          assistLabel.textContent = 'Anything the covering note should say? (optional)';
          assistPrompt.placeholder = 'ask Sam whether this affects the Friday release';
        } else {
          assistLabel.textContent = 'What should this message say?';
          assistPrompt.placeholder = "ask them to move Thursday's meeting to Friday morning";
        }
        assistSay('');
        assistPrompt.focus();
      });

      assistBar.querySelector('[data-assist-cancel]').addEventListener('click', function () {
        assistBar.hidden = true;
        assistSay('');
      });

      assistPrompt.addEventListener('keydown', function (evt) {
        // Enter drafts. Without this it submits the form, which sends the
        // message -- the worst possible outcome for a key pressed in a box
        // that is asking a question.
        if (evt.key === 'Enter') { evt.preventDefault(); assistGo.click(); }
        else if (evt.key === 'Escape') { evt.preventDefault(); assistBar.hidden = true; }
      });

      // The values htmx sends, added to the request it is already making.
      //
      // Not hx-vals="js:...": this app's CSP has no 'unsafe-eval' and htmx
      // compiles a js: value with new Function, so the browser would refuse it
      // and the request would go out with none of these in it -- silently.
      // configRequest is the documented way to do this under a CSP worth
      // having, and it keeps them in the same closure as the editor they are
      // read from.
      // htmx does the request; this decides what happens to the answer,
      // because the answer is text going into a rich-text surface that
      // already holds a quote below it.
      assistGo.addEventListener('htmx:configRequest', function (evt) {
        var instruction = assistPrompt.value.trim();
        if (!hasQuote && !instruction) {
          evt.preventDefault();
          assistSay('Say what the message should be about.', true);
          assistPrompt.focus();
          return;
        }
        var p = evt.detail.parameters;
        p.kind = assistKind;
        p.instruction = instruction;
        // Whatever is already in the composer, which for a reply is the quote
        // this app put there. Nothing else is read: the model is told about
        // the message being answered, not the mailbox.
        p.quoted = hasQuote ? currentBodyText() : '';
        // A count, never the addresses. It is the difference between writing
        // to a person and writing to a room, and it is all the model needs.
        if (assistKind === 'replyall') p.recipients = String(countRecipients());

        assistGo.disabled = true;
        assistSay('Drafting\u2026');
      });

      assistGo.addEventListener('htmx:afterRequest', function (evt) {
        assistGo.disabled = false;
        var xhr = evt.detail.xhr;
        if (!evt.detail.successful || !xhr || xhr.status >= 400) {
          assistSay((xhr && xhr.responseText) || 'The model could not be reached.', true);
          return;
        }
        insertDraftText(xhr.responseText);
        assistBar.hidden = true;
        assistSay('');
      });

      function currentBodyText() {
        return rich.hidden ? textarea.value : surface.innerText;
      }

      // Counted from the live fields rather than from what the server put
      // there, because the user may have added or removed somebody before
      // pressing the button.
      function countRecipients() {
        var n = 0;
        ['to', 'cc'].forEach(function (name) {
          var el = form.querySelector('[name=' + name + ']');
          if (!el) return;
          el.value.split(',').forEach(function (part) {
            if (part.trim() !== '') n++;
          });
        });
        return n;
      }

      // The draft goes in *above* whatever is already there, because what is
      // already there is usually the quoted message being replied to -- and a
      // reply belongs above its quote, which is where the caret would have
      // been anyway.
      function insertDraftText(text) {
        if (!text) return;
        if (rich.hidden) {
          textarea.value = text + '\n\n' + textarea.value;
          textarea.focus();
          textarea.setSelectionRange(text.length, text.length);
        } else {
          var frag = document.createElement('div');
          text.split('\n').forEach(function (line) {
            var div = document.createElement('div');
            if (line === '') div.appendChild(document.createElement('br'));
            else div.textContent = line;   // text, never markup -- see handleComposeAssist
            frag.appendChild(div);
          });
          frag.appendChild(document.createElement('div')).appendChild(
            document.createElement('br'));
          surface.insertBefore(frag, surface.firstChild);
          // Unwrap the holder so the editor is not left with a stray div
          // wrapping half the message.
          while (frag.firstChild) surface.insertBefore(frag.firstChild, frag);
          surface.removeChild(frag);
          surface.focus();
        }
        sync();
      }
    }

    // -- autosaving to Drafts ----------------------------------------------
    // Clicking a message in the list while composing should not throw the
    // message away. The click is an ordinary link, so it is intercepted, the
    // draft is posted, and the navigation is then done by hand.
    //
    // Deliberately not a timer. A draft saved every thirty seconds writes a
    // message nobody asked for and leaves one behind whenever the save happens
    // to land after the last edit; saving on the way out means the stored copy
    // is always exactly what was on screen when the user left.
    var draftUID = form.querySelector('[data-draft-uid]');
    var sending = false;
    form.addEventListener('submit', function () { sending = true; });

    // Untouched matters more than empty: a reply opens with the quoted text
    // already in it, and saving that verbatim would file a draft for every
    // reply anyone opened and thought better of.
    var initial = null;
    function snapshot() {
      return [textarea.value, surface.innerHTML,
        form.querySelector('[name=to]').value,
        form.querySelector('[name=cc]').value,
        form.querySelector('[name=bcc]').value,
        form.querySelector('[name=subject]').value,
        attachSnapshot()]
        // An escape, not a literal separator character. It was a raw NUL
        // byte, which JavaScript is perfectly happy with but which makes
        // every text tool treat this file as binary -- grep silently
        // matches nothing in it, which is its own small trap.
        // Still \u0000 rather than a space: joining with a space lets
        // "a" + "b c" and "a b" + "c" produce the same snapshot, so an
        // edit that moved text between two fields would read as clean.
        .join('\u0000');
    }
    initial = snapshot();
    function isDirty() { return snapshot() !== initial; }

    function saveDraft() {
      sync();
      var body = new FormData(form);
      body.append('ajax', '1');
      // keepalive, so the request survives the navigation that triggered it.
      return fetch('/app/compose/draft', {
        method: 'POST', body: body, keepalive: true, credentials: 'same-origin'
      }).then(function (res) { return res.json(); }).then(function (data) {
        if (data && data.uid && draftUID) draftUID.value = data.uid;
        initial = snapshot();
        return data;
      });
    }

    // Capture phase, so this runs before anything else decides what the click
    // meant. Only plain left clicks are taken: a modifier or a middle click
    // opens a new tab and leaves this composer exactly where it is.
    document.addEventListener('click', function (evt) {
      if (sending || !form.isConnected || !isDirty()) return;
      if (evt.defaultPrevented || evt.button !== 0) return;
      if (evt.metaKey || evt.ctrlKey || evt.shiftKey || evt.altKey) return;
      var link = evt.target.closest && evt.target.closest('a[href]');
      if (!link || link.target === '_blank') return;
      if (form.contains(link)) return;          // the composer's own Close
      var href = link.getAttribute('href');
      if (!href || href.charAt(0) === '#') return;

      evt.preventDefault();
      evt.stopPropagation();
      saveDraft()
        .catch(function () { /* the navigation matters more than the report */ })
        .then(function () { window.location.href = link.href; });
    }, true);

    // The tab closing, or the address bar being used. sendBeacon rather than
    // fetch: the page is going away and a normal request would be cancelled
    // with it. It cannot report back, so the UID is not updated -- which is
    // survivable, because the page holding that UID is the one being closed.
    window.addEventListener('pagehide', function () {
      if (sending || !isDirty() || !navigator.sendBeacon) return;
      var body = new FormData(form);
      body.append('ajax', '1');
      navigator.sendBeacon('/app/compose/draft', body);
    });

    // Whichever radio came back from the server decides the opening state.
    // No content is moved: the server has already put each body where it
    // belongs, and moving here would overwrite one with the other.
    var checked = form.querySelector('input[name=format]:checked');
    applyFormat(checked ? checked.value : 'plain', false);
  }

  // 7. The new-folder dialog: Escape, and the caret in the right place.
  //
  // Opening and closing is the checkbox's job and works with no script at
  // all -- this only adds the two things a checkbox cannot do. Delegated from
  // the document because the sidebar is re-rendered on every navigation.
  document.addEventListener('change', function (evt) {
    var box = evt.target;
    if (!box.dataset || box.dataset.folderDialog === undefined || !box.checked) return;
    var name = document.querySelector('[data-folder-name]');
    if (name) { name.focus(); name.select(); }
  });
  document.addEventListener('keydown', function (evt) {
    if (evt.key !== 'Escape') return;
    var open = document.querySelector('[data-folder-dialog]:checked');
    if (!open) return;
    open.checked = false;
    // Back to the checkbox, which is this control's tab stop -- leave focus
    // inside the closed dialog and the next Tab starts from the top of the
    // page. The CSS draws its focus ring on the visible label.
    open.focus();
  });
  // A dialog that reopened itself because the server refused the name wants
  // the caret in the field, same as one opened by hand.
  (function focusReopened() {
    var open = document.querySelector('[data-folder-dialog]:checked');
    if (!open) return;
    var name = document.querySelector('[data-folder-name]');
    if (name) { name.focus(); name.select(); }
  })();

  // 8. The three timing settings from Settings > General.
  //
  // Read from <meta> rather than fetched: the server already knew all three at
  // render time. They are meta tags rather than an inline script because the
  // CSP is `script-src 'self'` with no nonce, so an inline script would not
  // run at all.
  function metaNumber(name) {
    var el = document.querySelector('meta[name="' + name + '"]');
    var n = el ? parseInt(el.getAttribute('content'), 10) : 0;
    return isNaN(n) ? 0 : n;
  }

  // 8a. Mark the open message read after it has been open long enough.
  //
  // The wait is here rather than on the server because the server would have
  // to either hold a request open or mark a message read after the user had
  // already closed it -- which is the exact thing a delay is for.
  // The reading delay is not counted here. It is a trigger on the row --
  // hx-trigger="load delay:Ns" -- which fires once, N seconds after the row
  // arrives, and is cancelled by the row being replaced. See msg-row.
  //
  // It was a setTimeout here, re-armed on every swap, and it needed three
  // guards to stop it re-arming from the result of its own request. The
  // trigger needs none: an element that is gone cannot fire.

  // 8b. Reload the message list on an interval.
  //
  // Only on the mailbox itself, and never while a composer is open: reloading
  // the page out from under somebody typing a message is the worst thing this
  // timer could do.
  (function checkMailPeriodically() {
    // Seconds now, and already clamped to the deployment's floor by the
    // server -- so this timer never has to decide whether a value is allowed,
    // only how long to wait.
    var secs = metaNumber('mc-check-seconds');
    if (secs <= 0) return;
    setInterval(function () {
      if (document.querySelector('form[data-compose]')) return;
      if (document.querySelector('[data-folder-dialog]:checked')) return;
      // A hidden tab is not being read, so refreshing it is a round trip
      // nobody asked for. The next tick after it is shown picks it up.
      if (document.hidden) return;
      window.location.reload();
    }, secs * 1000);
  })();

  // 8c. Telling the server which timezone this browser is in.
  //
  // A session ends at 4am local time, and "local" has to mean where the person
  // is rather than where the server is -- one deployment serves people in more
  // than one place. The browser is the only party that knows, and the sign-in
  // form is the one moment it can say so without an extra request.
  //
  // Nothing depends on it: with scripting off the field stays empty and the
  // server falls back to its own zone. The value is an IANA name and is
  // validated server-side before it is trusted.
  (function reportTimezone() {
    var fields = document.querySelectorAll('input[data-timezone]');
    if (!fields.length) return;
    var tz = '';
    try {
      tz = Intl.DateTimeFormat().resolvedOptions().timeZone || '';
    } catch (e) {
      return;                                    // older browser: leave it empty
    }
    fields.forEach(function (f) { f.value = tz; });
  })();

  // 8d. The open-message highlight used to be fixed up here, after every swap.
  //
  // It is the server's now. The comment that used to be here said the server
  // "has no way to know which one it was" -- true when it was written, and
  // untrue from the moment viewState started holding the open message. The
  // handler that acted on it went stale without ever failing loudly: it looked
  // for the reading pane's `uid` field, which no longer exists, and for
  // `a.msg`, which is a <button> now. So it stripped the highlight from rows
  // it should have left alone and left `aria-current` on the row it should
  // have cleaned -- a screen reader announcing two current messages, which is
  // exactly the kind of thing nobody sees.
  //
  // renderReader sends the previously-open row back out-of-band instead; see
  // PageData.PrevOpenUID.

  // 8e. The unread badge, when a message is opened.
  //
  // Opening an unread message takes one off its folder's count. The server
  // knows that, but saying so would mean re-reading the folder list over IMAP
  // and sending a pane of sidebar markup back in answer to a click on a
  // message -- so the number is adjusted here instead, from what the page can
  // already see: the row was bold before the click and is not afterwards.
  //
  // Presentation of a number, not the number itself. Anything that fetches
  // folders -- a folder click, the list poll, a page load -- replaces it with
  // the server's own count, so a drift cannot persist.
  (function unreadBadge() {
    var pending = null;
    document.body.addEventListener('htmx:configRequest', function (evt) {
      var link = evt.detail.elt;
      if (!link || !link.closest) return;
      var row = link.closest('.msg-row');
      pending = row && row.classList.contains('unread') ? row.id : null;
    });
    document.body.addEventListener('htmx:afterSwap', function () {
      if (!pending) return;
      var row = document.getElementById(pending);
      pending = null;
      // Only if it actually stopped being unread: whether opening a message
      // marks it read is a setting, and with a delay set it is still unread
      // now and marked later by the timer above.
      if (!row || row.classList.contains('unread')) return;
      var badge = document.querySelector('.folder[aria-current="true"] .folder-count');
      if (!badge) return;
      var n = parseInt(badge.textContent, 10);
      if (isNaN(n)) return;
      if (n <= 1) badge.remove();               // no badge at zero, as the server draws it
      else badge.textContent = n - 1;
    });
  })();

  // 9. The PGP private key held in this browser.
  //
  // What is in localStorage is **ciphertext**: the server seals it under
  // secret_key before handing it back, so a stolen browser profile is useless
  // without that server. The browser has no access to secret_key and must not
  // -- which is also why "keep it in this browser" does not mean the key is
  // never sent here. It means the server does not keep it.
  //
  // The storage key is namespaced by mailbox address, so two accounts used in
  // one browser cannot collide and neither can read the other's.
  (function pgpLocalKey() {
    var form = document.querySelector('[data-pgp-form]');
    if (!form) return;
    var mailbox = document.querySelector('meta[name="mc-mailbox"]');
    var who = mailbox ? mailbox.getAttribute('content') : '';
    if (!who) return;
    var storeKey = 'mc.pgp.privkey.' + who.toLowerCase();

    function get() { try { return window.localStorage.getItem(storeKey) || ''; } catch (e) { return ''; } }
    function put(v) { try { window.localStorage.setItem(storeKey, v); } catch (e) { /* private mode, quota */ } }
    function drop() { try { window.localStorage.removeItem(storeKey); } catch (e) { /* as above */ } }

    // The server hands the freshly sealed key back on the redirect after a
    // save, in browser mode, because it is not keeping a copy. Taken out of
    // the URL immediately: a query string lands in history and in any log
    // that records URLs, and there is no reason for it to sit there.
    var params = new URLSearchParams(window.location.search);
    var sealed = params.get('store');
    if (sealed) {
      put(sealed);
      params.delete('store');
      var clean = window.location.pathname +
        (params.toString() ? '?' + params.toString() : '');
      window.history.replaceState({}, '', clean);
    }

    var storageToggle = form.querySelector('[data-pgp-storage]');
    var status = form.querySelector('[data-pgp-local-status]');

    function describe() {
      if (!status) return;
      if (storageToggle && storageToggle.checked) {
        status.textContent = get()
          ? 'A key is held in this browser.'
          : 'No key is held in this browser yet.';
      } else {
        status.textContent = 'No key is stored on the server.';
      }
    }
    describe();
    if (storageToggle) storageToggle.addEventListener('change', describe);

    // Switching back to server storage: the browser copy is no longer the
    // authority and leaving it behind would mean two keys, one of them stale
    // and invisible.
    form.addEventListener('submit', function () {
      if (storageToggle && !storageToggle.checked) drop();
    });
  })();

  // 10. The composer's sign and encrypt switches.
  //
  // Two jobs, both of which the form cannot do on its own. The passphrase box
  // appears only once something is going to need it -- a passphrase field on
  // every composer is a field people type into for no reason. And where the
  // private key lives in this browser, the sealed bytes have to travel with
  // the send: the server keeps no copy, so without this the send fails with
  // "no private key is available" on the one machine that actually has it.
  function initComposePGP(form) {
    var box = form.querySelector('[data-pgp]');
    if (!box) return;
    var sign = form.querySelector('[data-pgp-sign]');
    var encrypt = form.querySelector('[data-pgp-encrypt]');
    var pass = form.querySelector('[data-pgp-pass]');
    var sealed = form.querySelector('[data-pgp-sealed]');

    function wanted() {
      return (sign && sign.checked) || (encrypt && encrypt.checked);
    }
    function sync() {
      if (!pass) return;
      // **The wrapper, not the input.** Section 3 puts every password field
      // inside a .pw-wrap with a Show button beside it, and hiding the input
      // alone leaves that button floating over whatever is next to it -- which
      // is exactly what it did, sitting on top of the Encrypt label.
      var host = (pass.closest && pass.closest('.pw-wrap')) || pass;
      // Once the wrapper exists it owns the visibility, so the attribute the
      // template started with has to come off the input -- otherwise showing
      // the wrapper reveals an empty box with a Show button and no field in
      // it, which is what it did.
      if (host !== pass) pass.hidden = false;
      host.hidden = !wanted();
      // Cleared on the way out rather than left in a hidden field. A
      // passphrase typed and then un-ticked should not still be posted.
      if (host.hidden) pass.value = '';
    }
    if (sign) sign.addEventListener('change', sync);
    if (encrypt) encrypt.addEventListener('change', sync);
    sync();

    if (!sealed) return;
    var mailbox = document.querySelector('meta[name="mc-mailbox"]');
    var who = mailbox ? mailbox.getAttribute('content') : '';
    if (!who) return;
    var storeKey = 'mc.pgp.privkey.' + who.toLowerCase();

    form.addEventListener('submit', function (evt) {
      if (!wanted()) {
        // Not sent when it is not needed. The sealed key is a secret, and a
        // secret that rides along on every ordinary send is a secret in every
        // request log for no benefit.
        sealed.value = '';
        return;
      }
      var v = '';
      try { v = window.localStorage.getItem(storeKey) || ''; } catch (e) { v = ''; }
      sealed.value = v;
      if (!v && evt) {
        // Said here rather than letting the server answer, because the server
        // cannot tell this apart from a key that was never set up: from its
        // side both are an empty field. This browser is the only place that
        // knows the key is meant to be here and is not.
        evt.preventDefault();
        var msg = 'This mailbox keeps its private key in the browser, and this ' +
          'browser does not have it. Paste the key in Settings on this ' +
          'machine, or send without signing.';
        var note = form.querySelector('[data-pgp-note]');
        if (!note) {
          // Written into the page rather than into an alert(). A modal blocks
          // the whole document, and this is a message about a form the user is
          // still holding open.
          note = document.createElement('div');
          note.className = 'notice-bar';
          note.setAttribute('data-pgp-note', '');
          box.parentNode.insertBefore(note, box.parentNode.firstChild);
        }
        note.textContent = msg;
      }
    });
  }

  // 11. Controls that apply themselves.
  //
  // A switch whose state only takes effect after a separate Save is a switch
  // that lies: it slides over, looks on, and the setting beneath it still says
  // off. That is exactly how the two-factor toggle read before this existed.
  //
  // It is here rather than an inline onchange because this app's CSP has no
  // unsafe-inline, so an on* attribute is dead markup -- markup that looks like
  // a working control and silently is not. The form still submits normally, so
  // the Save button in the <noscript> beside it remains the path for anybody
  // this script does not reach.
  (function submitOnChange() {
    document.addEventListener('change', function (evt) {
      var el = evt.target;
      if (!el || !el.hasAttribute || !el.hasAttribute('data-submit-on-change')) return;
      var form = el.form || el.closest('form');
      if (!form) return;
      // Guard against a double submit from a second change event while the
      // navigation is already under way -- a toggle flipped twice quickly
      // would otherwise post twice, and for two-factor the second post is the
      // one that would reissue a secret.
      if (form.dataset.submitting === '1') return;
      form.dataset.submitting = '1';
      // requestSubmit, not submit: submit() skips validation and, more to the
      // point here, does not fire the submit event that other handlers on this
      // page listen for.
      if (form.requestSubmit) form.requestSubmit();
      else form.submit();
    });
  })();

  // ---------------------------------------------------------------------
  // 12. The live TOTP code on the two-factor setup screen.
  //
  // The panel exists so somebody can check their phone shows the same six
  // digits as this server *before* signing out. A code lasts thirty seconds,
  // so a page rendered once shows a number that is wrong within half a minute
  // -- and a mismatch there reads as "enrolment failed", which is the one
  // conclusion it must not invite.
  //
  // The countdown runs locally and only the code itself is fetched, so an open
  // settings tab costs one small request every thirty seconds rather than one
  // a second. The seconds remaining come back with each code, so the panel
  // re-syncs to the server's clock on every refresh instead of drifting.
  function initTOTPCode(root) {
    var panel = (root || document).querySelector('[data-totp-code]');
    if (!panel) return;
    var secs = panel.querySelector('[data-totp-seconds]');
    var plural = panel.querySelector('[data-totp-plural]');
    var left = parseInt(panel.getAttribute('data-expires'), 10);
    if (!secs || isNaN(left)) return;

    // Display only. Fetching the next code is htmx's -- the panel carries
    // hx-trigger="load delay:Ns" and replaces itself when this one expires,
    // which is why there is no request, no re-entrancy flag and no
    // visibilitychange handler here any more. All this does is count the
    // number down between those swaps.
    var timer = setInterval(function () {
      // The panel htmx swapped out takes its interval with it.
      if (!panel.isConnected) { clearInterval(timer); return; }
      if (left <= 0) return;
      left -= 1;
      secs.textContent = left;
      if (plural) plural.textContent = left === 1 ? '' : 's';
    }, 1000);
  }
  initTOTPCode(document);

  function initComposers(root) {
    (root || document).querySelectorAll('form[data-compose]').forEach(function (f) {
      initComposer(f);
      initComposePGP(f);
    });
  }
  initComposers(document);
  document.body.addEventListener('htmx:load', function (evt) {
    initComposers(evt.target);
    // The settings screens arrive as fragments, so the panel is often not in
    // the document at first load.
    initTOTPCode(evt.target);
  });
})();
