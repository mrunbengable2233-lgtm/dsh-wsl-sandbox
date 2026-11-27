                                                                 

/**
 * Structural TypeScript interfaces for the DeepSeek Harness (DSH) Cordis host context.
 * Supports BOTH real `@deepseek-ai/dsh` (>=0.2.1-rc.1 / 0.2.2-rc.5) services AND lightweight
 * standalone coexistence test harnesses, while keeping zero runtime npm dependencies.
 */

                                                  

                            
                                              
                                              
                                               
                                                
 

                                                                                         

                                  
                        
                        
 

                                          
                                                     
                                                           
 

                                  
                           
                              
                           
                                
 

                                                                                         
                        
                               
                                                         
                                           
                                                          
                                                                                
 

                                       
                        
                              
                           
                           
                                
 

                                     
                          
                   
                          
                          
                             
    
 

                            
                                            
                                             

                                  
                                                         
                                                
                              
 

                                         
                      
                         
                                                              
 

                                       
                        
                         
                                 
                                                          
 

                                         
                                                  
                                                      
                                               
                                                              
 

                                         
                           
                              
                         
                            
                            
                                       
                                           
                                      
                                                  
                           
                             
                           
                           
                                
 

                                        
                                                                                         
                             
                                             
                              
                                     
                                   
                           
 

                                    
                  
                    
                     
                
                        
             
           
              
               
                  

                                     
                                                                                                                
 

                                 
                          
                        
                                                    
                                                   
                          
                                                                 
 

                                  
                                        
                                                       
                               
                              
                              
 

                                                                                                 

                                
                                                                                                           
 

/** Real `@deepseek-ai/dsh-host-webserver` route contract */
                                    
                                    
                        
                                                                                        
 

                               
                         
                         
                             
                                                 
 

                                    
                              
                                   

                                       
                                            
                                                       
 

                                           
                             
                                           
                              
                           
                                                        
                         
                               
                           
                                
 

                                
                              
     
                            
                              
                                                                                                 
     
                               
                                                       

                                                                 
                    
                               
                      

                                   
                                   
                                                 
                                         
                                    
                                             
                                
                                   
                              
                                                                                                   
                                                                    
                                             
                  
                                                      
                                       
                                                
                                                    
                  
                                                      
                     
                                                                                     
 

/**
 * 统一订阅 Cordis 瀑布流钩子：
 * - 在真实 `@deepseek-ai/dsh`（Cordis 4）中必须调用 `ctx.on(event, listener)`（若误调 `ctx.waterfall`
 *   会直接触发空事件派发导致 `TypeError: next is not a function`）。
 * - 仅当测试桩未实现 `ctx.on` 且显式提供 `ctx.waterfall` 注册方法时，兼容回退到 `ctx.waterfall`。
 */
export function subscribeCordisWaterfall                                       (
  ctx                  ,
  event        ,
  listener                                         ,
)                           {
  if (typeof ctx.on === 'function') {
    const dispose = ctx.on(event, listener);
    return typeof dispose === 'function' ? () => { void dispose(); } : undefined;
  }
  if (typeof ctx.waterfall === 'function') {
    const dispose = ctx.waterfall(event, listener);
    return typeof dispose === 'function' ? () => { void dispose(); } : undefined;
  }
  return undefined;
}

export function getOptionalService                                           (
  ctx                  ,
  key   ,
)                                  {
  if (typeof ctx.get === 'function') {
    return ctx.get(key)                                   ;
  }
  return ctx[key];
}
