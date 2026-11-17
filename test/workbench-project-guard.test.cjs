'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { getWebviewBody } = require('../out/webview/body.js');
const { getWebviewScriptWorkbench } = require('../out/webview/script-workbench.js');
const { getWebviewScriptValidation } = require('../out/webview/script-validation.js');
const vm = require('node:vm');
function node() { return { children: [], textContent: '', disabled: false, checked: false, listeners: {}, appendChild(x) { this.children.push(x); }, append(...x) { this.children.push(...x); }, replaceChildren(...x) { this.children=x; }, addEventListener(n,f) { this.listeners[n]=f; } }; }

test('Safe Simulation and Project Validation do not require a source file to be the active editor', () => {
  const body = getWebviewBody();
  assert.match(body, /workbench-project-state/);
  assert.match(body, /id="workbench-start" disabled/);
  assert.match(body, /id="workbench-runtime" disabled/);
  const ids = ['workbench-profile','workbench-status','workbench-output','workbench-runtime-status','workbench-runtime-output','workbench-runtime','workbench-runtime-consent','workbench-start','workbench-cancel','workbench-save-status','workbench-network','workbench-limitations','workbench-project-state'];
  const elements = Object.fromEntries(ids.map(id=>[id,node()]));
  elements['workbench-start'].click = function(){ this.listeners.click?.({ target:this }); };
  const listeners={}; const messages=[];
  vm.runInNewContext(getWebviewScriptWorkbench(), { document:{getElementById:id=>elements[id],createElement:()=>node()}, window:{addEventListener:(n,f)=>listeners[n]=f}, vscode:{postMessage:m=>messages.push(m)} });
  listeners.message({data:{type:'workbenchCapabilities',capabilities:{profiles:[{id:'source',supported:true}],limitations:[],workspace:{open:false,projectFiles:0,ready:false,reason:'Open a VS Code workspace.'}}}});
  assert.equal(elements['workbench-start'].disabled,true);
  assert.equal(elements['workbench-runtime'].disabled,true);
  assert.match(elements['workbench-project-state'].textContent,/Open a VS Code project folder/);
  elements['workbench-start'].listeners.click();
  assert.equal(messages.some(m=>m.type==='workbenchStart'),false);
  listeners.message({data:{type:'workbenchWorkspaceState',workspace:{open:true,projectFiles:0,selectedProjectFile:false,ready:false,reason:'This workspace contains no supported project source files.'}}});
  assert.equal(elements['workbench-start'].disabled,true,'a workspace with no supported source files must be blocked');
  assert.match(elements['workbench-project-state'].textContent,/no supported project source files/);
  listeners.message({data:{type:'workbenchWorkspaceState',workspace:{open:true,projectFiles:12,selectedProjectFile:false,selectedFile:'',ready:true,reason:''}}});
  assert.equal(elements['workbench-start'].disabled,false);
  assert.match(elements['workbench-project-state'].textContent,/source file\(s\) ready/);
  const validation = getWebviewScriptValidation();
  assert.match(validation, /Safe Simulation/);
  assert.match(validation, /Project Validation/);
  const extension = require('node:fs').readFileSync(require('node:path').join(__dirname, '../src/extension.ts'), 'utf8');
  const runtimeHandler = extension.slice(extension.indexOf('async function runSandboxAttack('));
  assert.doesNotMatch(runtimeHandler, /activeTextEditor/);
});
