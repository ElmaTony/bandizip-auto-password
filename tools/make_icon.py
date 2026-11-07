"""Generate the Windows icon from the same geometric mark as assets/icon.svg."""
from pathlib import Path
from PIL import Image, ImageDraw
root=Path(__file__).resolve().parents[1]
scale=4
im=Image.new('RGBA',(256*scale,256*scale))
d=ImageDraw.Draw(im)
def points(values):return [(x*scale,y*scale) for x,y in values]
d.rounded_rectangle((48,48,976,976),radius=240,fill='#4f46e5')
for path in [[(64,80),(192,80),(192,184),(64,184),(64,80)],[(64,80),(88,56),(168,56),(192,80)],[(128,58),(128,104)]]:
 d.line(points(path),fill='white',width=56,joint='curve')
d.ellipse((111*scale,120*scale,145*scale,154*scale),fill='white')
d.line(points([(128,145),(128,163)]),fill='white',width=48)
d.ellipse((122*scale,157*scale,134*scale,169*scale),fill='white')
im.resize((256,256),Image.Resampling.LANCZOS).save(root/'assets/app.ico',sizes=[(16,16),(24,24),(32,32),(48,48),(64,64),(128,128),(256,256)])
