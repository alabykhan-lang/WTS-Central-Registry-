'use strict';

(() => {
  const $ = (selector) => document.querySelector(selector);
  let photo = '';

  function message(code) {
    return ({
      FULL_NAME_REQUIRED: 'Enter your full name.',
      VALID_EMAIL_REQUIRED: 'Enter a valid email address.',
      PHONE_REQUIRED: 'Enter a phone number.',
      PHOTOGRAPH_INVALID: 'Choose a smaller photograph.',
      STAFF_REGISTRATION_ALREADY_ON_FILE: 'A registration or staff identity is already on file for these contact details.',
    })[code] || String(code || 'Registration could not be submitted.').replaceAll('_', ' ').toLowerCase();
  }

  async function compressPhoto(file) {
    if (!file?.type?.startsWith('image/')) throw new Error('Choose an image file.');
    if (file.size > 12 * 1024 * 1024) throw new Error('Choose a photo below 12 MB.');
    const source = 'createImageBitmap' in window
      ? await createImageBitmap(file, { imageOrientation: 'from-image' })
      : await new Promise((resolve, reject) => { const image = new Image(); image.onload = () => resolve(image); image.onerror = reject; image.src = URL.createObjectURL(file); });
    const max = 560;
    const scale = Math.min(1, max / Math.max(source.width, source.height));
    const canvas = document.createElement('canvas');
    canvas.width = Math.max(1, Math.round(source.width * scale));
    canvas.height = Math.max(1, Math.round(source.height * scale));
    const context = canvas.getContext('2d');
    context.fillStyle = '#fff';
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.drawImage(source, 0, 0, canvas.width, canvas.height);
    source.close?.();
    let quality = 0.76;
    let data = canvas.toDataURL('image/jpeg', quality);
    while (data.length > 180000 && quality > 0.42) { quality -= 0.08; data = canvas.toDataURL('image/jpeg', quality); }
    if (data.length > 220000) throw new Error('Use a smaller photo.');
    return data;
  }

  async function choosePhoto(file) {
    try {
      photo = await compressPhoto(file);
      $('#registrationPhoto').value = photo;
      $('#registrationPhotoPreview').src = photo;
      $('#registrationError').textContent = 'Photo ready.';
    } catch (error) {
      $('#registrationError').textContent = error.message;
    }
  }

  $('#registrationGallery').onchange = (event) => choosePhoto(event.target.files[0]);
  $('#registrationCamera').onchange = (event) => choosePhoto(event.target.files[0]);
  $('#removeRegistrationPhoto').onclick = () => {
    photo = '';
    $('#registrationPhoto').value = '';
    $('#registrationPhotoPreview').removeAttribute('src');
  };
  $('#staffRegistrationForm').onsubmit = async (event) => {
    event.preventDefault();
    const button = $('#submitRegistration');
    button.disabled = true;
    $('#registrationError').textContent = 'Submitting…';
    try {
      const values = Object.fromEntries(new FormData(event.currentTarget).entries());
      const response = await fetch('/api/staff-registration', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(values),
      });
      const result = await response.json().catch(() => ({ ok: false, code: 'INVALID_RESPONSE' }));
      if (!response.ok || result?.ok === false) throw Object.assign(new Error(message(result?.code)), { code: result?.code });
      $('#staffRegistrationForm').hidden = true;
      $('#registrationSuccess').hidden = false;
    } catch (error) {
      $('#registrationError').textContent = message(error.code || error.message);
    } finally {
      button.disabled = false;
    }
  };
})();
