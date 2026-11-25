                              
                   
                    
                         
                         
                                
                  
                   
                   
                    
                      
                        
                    
                  
                    
                       
                  
             
               
                   

                                      
                                  
 

export class SandboxError extends Error {
           code                  ;
           details                      ;

  constructor(code                  , message         , details                      ) {
    super(message ?? code);
    this.name = 'SandboxError';
    this.code = code;
    if (details !== undefined) {
      this.details = details;
    }
  }
}

export function failSandbox(
  code                  ,
  message         ,
  details                      ,
)        {
  throw new SandboxError(code, message, details);
}

export function isSandboxError(err         )                      {
  return err instanceof SandboxError;
}
