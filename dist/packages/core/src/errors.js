                              
                   
                    
                         
                         
                                
                  
                   
                   
                    
                      
                        
                    
                  
                    
                       
                  
             
               
                   

                                      
                                  
 

export class SandboxError extends Error {
           code                  ;
           details                      ;

  constructor(
    code                  ,
    message         ,
    details                      ,
    options               ,
  ) {
    super(message ?? code, options);
    this.name = 'SandboxError';
    this.code = code;
    if (details !== undefined) {
      this.details = details;
    }
    Error.captureStackTrace?.(this, SandboxError);
  }
}

export function failSandbox(
  code                  ,
  message         ,
  details                      ,
  options               ,
)        {
  throw new SandboxError(code, message, details, options);
}

export function isSandboxError(err         )                      {
  return err instanceof SandboxError;
}
