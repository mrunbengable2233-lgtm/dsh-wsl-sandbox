import {                                      spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import readline from 'node:readline';

/**
 * Zero-execution official Windows PowerShell compiler AST bridge wrapping
 * `[System.Management.Automation.Language.Parser]::ParseInput` and `::ParseFile`
 * inside a reusable `-NoProfile -NonInteractive` PowerShell worker process.
 *
 * Security guarantee: ONLY calls static `[Parser]::ParseInput` / `[Parser]::ParseFile`
 * (never `Invoke-Expression`, scriptblock `.Invoke()`, or command execution).
 */

                                           
                        
                        
                                 
                                         
                                        
                                         
                                                 
 

                                            
                          
                           
                              
                                       
 

                                        
                        
                                      
                                                         
                                      
                                                               
 

                                       
                           
                           
                          
 

                                      
                        
                        
                                 
 

                                             
                        
                              
                          
                                                     
 

                                       
                                        
                                                      
                                                                     
                                                              
                                             
                                   
                                         
                                                   
 

                                            
                       
                                         
                              
                                                   
                          
 

const WORKER_SCRIPT = [
  '[Console]::InputEncoding = [System.Text.Encoding]::UTF8',
  '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
  '$chainType = "System.Management.Automation.Language.PipelineChainAst" -as [type]',
  'while ($null -ne ($line = [Console]::In.ReadLine())) {',
  '  if ([string]::IsNullOrWhiteSpace($line)) { continue }',
  '  $id = ""',
  '  try {',
  '    $req = $line | ConvertFrom-Json',
  '    $id = [string]$req.id',
  '    $shellName = if ($PSVersionTable.PSVersion.Major -ge 6) { "pwsh" } else { "powershell" }',
  '    $tokens = $null',
  '    $errors = $null',
  '    if ($null -ne $req.PSObject.Properties["filePath"] -and -not [string]::IsNullOrWhiteSpace([string]$req.filePath)) {',
  '      $fp = [string]$req.filePath',
  '      if (-not (Test-Path -LiteralPath $fp -PathType Leaf)) {',
  '        $missObj = [PSCustomObject]@{',
  '          id = $id',
  '          ok = $false',
  '          kind = "file"',
  '          shell = $shellName',
  '          errorCount = 1',
  '          errors = @([PSCustomObject]@{ message = "File not found: $fp"; errorId = "FileNotFound"; offset = 0 })',
  '          error = "File not found: $fp"',
  '        }',
  '        [Console]::Out.WriteLine(($missObj | ConvertTo-Json -Depth 5 -Compress))',
  '        continue',
  '      }',
  '      $null = [System.Management.Automation.Language.Parser]::ParseFile($fp, [ref]$tokens, [ref]$errors)',
  '      $fErrList = @()',
  '      foreach ($e in $errors) {',
  '        $fErrList += [PSCustomObject]@{',
  '          message = $e.Message',
  '          errorId = $e.ErrorId',
  '          offset = $e.Extent.StartOffset',
  '        }',
  '      }',
  '      $fileOut = [PSCustomObject]@{',
  '        id = $id',
  '        ok = ($fErrList.Count -eq 0)',
  '        kind = "file"',
  '        shell = $shellName',
  '        errorCount = $fErrList.Count',
  '        errors = @($fErrList)',
  '      }',
  '      [Console]::Out.WriteLine(($fileOut | ConvertTo-Json -Depth 5 -Compress))',
  '      continue',
  '    }',
  '    $code = [string]$req.code',
  '    $ast = [System.Management.Automation.Language.Parser]::ParseInput($code, [ref]$tokens, [ref]$errors)',
  '    $hasStop = $false',
  '    foreach ($tk in $tokens) {',
  '      if ($tk.Text -eq "--%" -and ($tk.Kind -eq "Generic" -or ([int]$tk.TokenFlags -band 32768) -ne 0)) {',
  '        $hasStop = $true',
  '        break',
  '      }',
  '    }',
  '    $cmds = @()',
  '    $hasDyn = $false',
  '    $cmdAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)',
  '    foreach ($c in $cmdAsts) {',
  '      $elems = @()',
  '      $dynHead = $false',
  '      $idx = 0',
  '      foreach ($el in $c.CommandElements) {',
  '        $tname = $el.GetType().Name',
  '        $val = $null',
  '        $pname = $null',
  '        $argText = $null',
  '        $argVal = $null',
  '        $nestedExprs = @()',
  '        $isSimpleConst = $false',
  '        if ($el -is [System.Management.Automation.Language.StringConstantExpressionAst]) {',
  '          $val = $el.Value',
  '          $isSimpleConst = $true',
  '        } elseif ($el -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) {',
  '          if ($el.NestedExpressions.Count -eq 0) {',
  '            $val = $el.Value',
  '            $isSimpleConst = $true',
  '          } else {',
  '            foreach ($ne in $el.NestedExpressions) {',
  '              $nestedExprs += $ne.Extent.Text',
  '            }',
  '          }',
  '        } elseif ($el -is [System.Management.Automation.Language.CommandParameterAst]) {',
  '          $pname = $el.ParameterName',
  '          if ($null -ne $el.Argument) {',
  '            $argText = $el.Argument.Extent.Text',
  '            if ($el.Argument -is [System.Management.Automation.Language.StringConstantExpressionAst]) {',
  '              $argVal = $el.Argument.Value',
  '            } elseif ($el.Argument -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $el.Argument.NestedExpressions.Count -eq 0) {',
  '              $argVal = $el.Argument.Value',
  '            }',
  '          }',
  '        }',
  '        if ($idx -eq 0 -and -not $isSimpleConst) {',
  '          $dynHead = $true',
  '          $hasDyn = $true',
  '        }',
  '        $elems += [PSCustomObject]@{',
  '          kind = $tname',
  '          text = $el.Extent.Text',
  '          value = $val',
  '          parameterName = $pname',
  '          argumentText = $argText',
  '          argumentValue = $argVal',
  '          nestedExpressions = @($nestedExprs)',
  '        }',
  '        $idx++',
  '      }',
  '      $cRedirs = @()',
  '      foreach ($cr in $c.Redirections) {',
  '        if ($cr -is [System.Management.Automation.Language.FileRedirectionAst]) {',
  '          $ctVal = $null',
  '          if ($cr.Location -is [System.Management.Automation.Language.StringConstantExpressionAst]) {',
  '            $ctVal = $cr.Location.Value',
  '          } elseif ($cr.Location -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $cr.Location.NestedExpressions.Count -eq 0) {',
  '            $ctVal = $cr.Location.Value',
  '          }',
  '          $cRedirs += [PSCustomObject]@{',
  '            stream = [string]$cr.FromStream',
  '            append = [bool]$cr.Append',
  '            targetText = $cr.Location.Extent.Text',
  '            targetValue = $ctVal',
  '          }',
  '        }',
  '      }',
  '      $cmds += [PSCustomObject]@{',
  '        text = $c.Extent.Text',
  '        invocationOperator = [string]$c.InvocationOperator',
  '        elements = @($elems)',
  '        dynamicInvocation = $dynHead',
  '        redirections = @($cRedirs)',
  '      }',
  '    }',
  '    $redirs = @()',
  '    $redirAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] }, $true)',
  '    foreach ($r in $redirAsts) {',
  '      $tVal = $null',
  '      if ($r.Location -is [System.Management.Automation.Language.StringConstantExpressionAst]) {',
  '        $tVal = $r.Location.Value',
  '      } elseif ($r.Location -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $r.Location.NestedExpressions.Count -eq 0) {',
  '        $tVal = $r.Location.Value',
  '      }',
  '      $redirs += [PSCustomObject]@{',
  '        stream = [string]$r.FromStream',
  '        append = [bool]$r.Append',
  '        targetText = $r.Location.Extent.Text',
  '        targetValue = $tVal',
  '      }',
  '    }',
  '    $memberInvocs = @()',
  '    $invokeAsts = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)',
  '    foreach ($inv in $invokeAsts) {',
  '      $mArgs = @()',
  '      foreach ($ma in $inv.Arguments) {',
  '        $mVal = $null',
  '        if ($ma -is [System.Management.Automation.Language.StringConstantExpressionAst]) {',
  '          $mVal = $ma.Value',
  '        } elseif ($ma -is [System.Management.Automation.Language.ExpandableStringExpressionAst] -and $ma.NestedExpressions.Count -eq 0) {',
  '          $mVal = $ma.Value',
  '        }',
  '        $mArgs += [PSCustomObject]@{',
  '          kind = $ma.GetType().Name',
  '          text = $ma.Extent.Text',
  '          value = $mVal',
  '        }',
  '      }',
  '      $mName = if ($inv.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $inv.Member.Value } else { $inv.Member.Extent.Text }',
  '      $memberInvocs += [PSCustomObject]@{',
  '        text = $inv.Extent.Text',
  '        expression = $inv.Expression.Extent.Text',
  '        member = $mName',
  '        arguments = @($mArgs)',
  '      }',
  '    }',
  '    $chains = @()',
  '    if ($null -ne $chainType) {',
  '      $chainAsts = $ast.FindAll({ param($n) $chainType.IsInstanceOfType($n) }, $true)',
  '      foreach ($ch in $chainAsts) {',
  '        $chains += [string]$ch.Operator',
  '      }',
  '    }',
  '    $errList = @()',
  '    foreach ($e in $errors) {',
  '      $errList += [PSCustomObject]@{',
  '        message = $e.Message',
  '        errorId = $e.ErrorId',
  '        offset = $e.Extent.StartOffset',
  '      }',
  '    }',
  '    $outObj = [PSCustomObject]@{',
  '      id = $id',
  '      ok = $true',
  '      kind = "input"',
  '      shell = $shellName',
  '      commands = @($cmds)',
  '      memberInvocations = @($memberInvocs)',
  '      redirections = @($redirs)',
  '      chainOperators = @($chains)',
  '      hasStopParsing = $hasStop',
  '      hasDynamicInvocation = $hasDyn',
  '      errors = @($errList)',
  '    }',
  '    [Console]::Out.WriteLine(($outObj | ConvertTo-Json -Depth 7 -Compress))',
  '  } catch {',
  '    $errObj = [PSCustomObject]@{',
  '      id = $id',
  '      ok = $false',
  '      error = $_.Exception.Message',
  '    }',
  '    [Console]::Out.WriteLine(($errObj | ConvertTo-Json -Depth 4 -Compress))',
  '  }',
  '}',
].join('\n');

const WORKER_ENCODED_CMD = Buffer.from(WORKER_SCRIPT, 'utf16le').toString('base64');
const MAX_CACHE_ENTRIES = 512;
const PARSE_TIMEOUT_MS = 5000;

                          
                                           
                                 
                                  
 

function normalizeArr   (v                            )      {
  return Array.isArray(v) ? v : v ? [v] : [];
}

class SystemPwshAstWorker {
          child                                            ;
          stdoutRl                                ;
          startPromise                              ;
          unavailable = false;
                   pending = new Map                        ();
                   cache = new Map                              ();

          unrefHandle(stream         )       {
    if (!stream || typeof stream !== 'object') return;
    const s = stream                                                            ;
    try { s.unref?.(); } catch { /* ignore */ }
    try { s._handle?.unref?.(); } catch { /* ignore */ }
  }

          spawnExecutable(exe                               )                   {
    return new Promise         ((resolve) => {
      let settled = false;
      let child                                ;
      try {
        child = spawn(
          exe,
          ['-NoProfile', '-NonInteractive', '-EncodedCommand', WORKER_ENCODED_CMD],
          {
            stdio: ['pipe', 'pipe', 'pipe'],
            shell: false,
            windowsHide: true,
          },
        );
      } catch {
        resolve(false);
        return;
      }

      // Guard pipe error events so early exit never throws EPIPE
      child.stdin.on('error', () => {});
      child.stdout.on('error', () => {});
      child.stderr.on('error', () => {});

      const finishStart = (ok         )       => {
        if (settled) return;
        settled = true;
        clearTimeout(startTimer);
        resolve(ok);
      };

      const startTimer = setTimeout(() => {
        if (this.child === child) {
          this.cleanupChild();
        }
        try { if (!child.killed && child.exitCode === null) child.kill(); } catch { /* ignore */ }
        finishStart(false);
      }, PARSE_TIMEOUT_MS);

      const onError = ()       => {
        if (this.child === child) {
          this.cleanupChild();
        }
        finishStart(false);
      };

      const onSpawn = ()       => {
        this.child = child;
        const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
        this.stdoutRl = rl;
        rl.on('line', (line) => this.handleLine(line));
        child.stderr.on('data', () => {});
        child.once('exit', () => {
          if (this.child === child) {
            this.cleanupChild();
          }
        });
        child.unref();
        this.unrefHandle(child.stdin);
        this.unrefHandle(child.stdout);
        this.unrefHandle(child.stderr);
        finishStart(true);
      };

      child.once('error', onError);
      child.once('spawn', onSpawn);
    });
  }

          cleanupChild()       {
    this.stdoutRl?.close();
    this.stdoutRl = undefined;
    const c = this.child;
    this.child = undefined;
    if (c) {
      try { c.stdin.end(); } catch { /* ignore */ }
      try { if (!c.killed && c.exitCode === null) c.kill(); } catch { /* ignore */ }
    }
    for (const [id, p] of this.pending) {
      clearTimeout(p.timer);
      p.resolve(p.fallbackValue);
      this.pending.delete(id);
    }
  }

          async ensureWorker()                   {
    if (process.platform !== 'win32' || this.unavailable) return false;
    if (this.child && !this.child.killed && this.child.exitCode === null && this.child.stdin.writable) {
      return true;
    }
    if (this.startPromise) return this.startPromise;

    this.startPromise = (async () => {
      if (await this.spawnExecutable('pwsh.exe')) return true;
      if (await this.spawnExecutable('powershell.exe')) return true;
      this.unavailable = true;
      return false;
    })();

    try {
      return await this.startPromise;
    } finally {
      this.startPromise = undefined;
    }
  }

          handleLine(line        )       {
    const trimmed = line.trim();
    if (!trimmed) return;
    let parsed   
                  
                   
                    
                                    
                                         
                                                       
                                                 
                                
                               
                                     
                          
                                      
                     
     ;
    try {
      parsed = JSON.parse(trimmed)                 ;
    } catch {
      return;
    }
    if (!parsed.id) return;
    const entry = this.pending.get(parsed.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.pending.delete(parsed.id);

    if (parsed.kind === 'file') {
      const errors = normalizeArr(parsed.errors);
      const fileResult                            = {
        ok: Boolean(parsed.ok),
        shell: parsed.shell === 'powershell' ? 'powershell' : 'pwsh',
        errorCount: typeof parsed.errorCount === 'number' ? parsed.errorCount : errors.length,
        errors,
        ...(parsed.error ? { error: parsed.error } : {}),
      };
      entry.resolve(fileResult);
      return;
    }

    if (!parsed.ok) {
      entry.resolve(entry.fallbackValue);
      return;
    }

    const summary                       = {
      shell: parsed.shell === 'powershell' ? 'powershell' : 'pwsh',
      commands: normalizeArr(parsed.commands).map((c) => ({
        ...c,
        elements: normalizeArr(c.elements                                                         ).map((el) => ({
          ...el,
          nestedExpressions: normalizeArr(el.nestedExpressions                                 ),
        })),
        redirections: normalizeArr(c.redirections                                                                       ),
      })),
      memberInvocations: normalizeArr(parsed.memberInvocations).map((m) => ({
        ...m,
        arguments: normalizeArr(m.arguments                                                           ),
      })),
      redirections: normalizeArr(parsed.redirections),
      chainOperators: normalizeArr(parsed.chainOperators),
      hasStopParsing: Boolean(parsed.hasStopParsing),
      hasDynamicInvocation: Boolean(parsed.hasDynamicInvocation),
      errors: normalizeArr(parsed.errors),
    };
    entry.resolve(summary);
  }

          async sendRequest   (payload                         , fallbackValue   )             {
    const ready = await this.ensureWorker();
    if (!ready || !this.child || !this.child.stdin.writable) return fallbackValue;

    const id = randomUUID();
    return new Promise   ((resolve) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        resolve(fallbackValue);
      }, PARSE_TIMEOUT_MS);
      this.pending.set(id, {
        resolve: resolve                          ,
        timer,
        fallbackValue,
      });
      try {
        this.child .stdin.write(JSON.stringify({ id, ...payload }) + '\n', (err) => {
          if (err) {
            clearTimeout(timer);
            this.pending.delete(id);
            resolve(fallbackValue);
          }
        });
      } catch {
        clearTimeout(timer);
        this.pending.delete(id);
        resolve(fallbackValue);
      }
    });
  }

  async parse(command        )                                       {
    if (process.platform !== 'win32' || !command) return null;
    const cached = this.cache.get(command);
    if (cached) return cached;

    const res = await this.sendRequest                             ({ code: command }, null);

    if (res) {
      if (this.cache.size >= MAX_CACHE_ENTRIES) {
        const oldest = this.cache.keys().next().value;
        if (oldest !== undefined) this.cache.delete(oldest);
      }
      this.cache.set(command, res);
    }
    return res;
  }

  async parseFile(filePath        )                                     {
    if (process.platform !== 'win32') {
      return {
        ok: false,
        errorCount: 0,
        errors: [],
        error: 'PowerShell system parser requires Windows (win32)',
      };
    }
    if (!filePath || filePath.trim().length === 0) {
      return {
        ok: false,
        errorCount: 1,
        errors: [{ message: 'Empty filePath', errorId: 'EmptyFilePath', offset: 0 }],
        error: 'Empty filePath',
      };
    }
    return this.sendRequest                           (
      { filePath },
      {
        ok: false,
        errorCount: 1,
        errors: [{ message: 'PowerShell parser worker unavailable or timed out', errorId: 'WorkerUnavailable', offset: 0 }],
        error: 'PowerShell parser worker unavailable or timed out',
      },
    );
  }

  async dispose()                {
    this.startPromise = undefined;
    const c = this.child;
    this.cleanupChild();
    if (c && c.exitCode === null) {
      await new Promise      ((resolve) => {
        const t = setTimeout(resolve, 300);
        c.once('exit', () => {
          clearTimeout(t);
          resolve();
        });
      });
    }
    this.cache.clear();
  }
}

const sharedWorker = new SystemPwshAstWorker();

export async function parsePwshWithSystemParser(command        )                                       {
  return sharedWorker.parse(command);
}

export async function parsePs1FileWithSystemParser(filePath        )                                     {
  return sharedWorker.parseFile(filePath);
}

export async function disposeSystemPwshParser()                {
  await sharedWorker.dispose();
}
