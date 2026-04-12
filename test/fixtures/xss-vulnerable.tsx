import React from 'react';

export function VulnerableComponent({ userInput, rawHtml }: { userInput: string; rawHtml: string }) {
  const el = document.getElementById('target');
  if (el) {
    el.innerHTML = userInput;
  }

  const result = eval(userInput);

  document.write('<div>' + userInput + '</div>');

  const container = document.querySelector('.box');
  if (container) {
    container.outerHTML = rawHtml;
  }

  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: rawHtml }} />
      <a href="javascript:alert('xss')">Click me</a>
      <a href={`javascript:${userInput}`}>Danger</a>
    </div>
  );
}

export function TimerXSS(code: string) {
  setTimeout('alert(document.cookie)', 0);
  const fn = new Function('return ' + code);
  return fn();
}
