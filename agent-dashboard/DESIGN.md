\# Recreate this Three.js scene: Starfield Close



You are an expert Three.js creative developer. Produce a \*\*single self-contained `index.html`\*\*

that renders the scene below \*\*exactly\*\* as specified — same geometry, shaders, colors, motion,

and postprocessing. Load Three.js \*\*r0.143.0\*\* via an ES-module importmap from unpkg; no build

step, no bundler, pure ES modules in one `<script type="module">`. Hardcode every value given

here as fixed constants.



\## What it looks like

A dense volume of bright stars wraps the camera and streams steadily past in tints of mint-green,

jade and bone, reading as an endless tunnel of starlight. Each star twinkles on its own phase

while the whole field slowly barrel-rolls; scrolling surges the drift and dives the camera forward

down the tunnel, and the cursor both steers the heading and gently pushes nearby stars aside.



\## Page \& boilerplate

\- importmap: `three` → `https://unpkg.com/three@0.143.0/build/three.module.js`, `three/addons/` →

&#x20; `https://unpkg.com/three@0.143.0/examples/jsm/`.

\- Black page (`html, body { margin:0; padding:0; background:#000 }`, `body { height:100% }`). A

&#x20; full-window fixed `<canvas id="scene">` (`position:fixed; inset:0; width:100vw; height:100vh; display:block`).

\- A tall scroll host `<div id="scroll-host" style="height:300vh"></div>` so the page scrolls (drives

&#x20; the camera dive). Optional uppercase "scroll ↓" hint pinned bottom-center.

\- Renderer: `new THREE.WebGL1Renderer({ canvas, antialias:true })`, `setPixelRatio(window.devicePixelRatio)`,

&#x20; `shadowMap.enabled = true`, `shadowMap.type = THREE.VSMShadowMap`.

\- Scene background `0x000000`; fog `new THREE.Fog(0x000000, 0, 15)`.

\- Camera: `new THREE.PerspectiveCamera(45, innerWidth/innerHeight, 0.1, 80)` at `(0, 0, 5)`.

\- \*\*Layers:\*\* define `LAYERS = { NONE:0, TORUS\_SCENE:1, BLOOM\_SCENE:2, ENTIRE\_SCENE:3 }`. Enable

&#x20; `TORUS\_SCENE`, `BLOOM\_SCENE`, `ENTIRE\_SCENE` on the camera; `scene.add(camera)`.

\- \*\*Postprocessing — three composers\*\* (each `EffectComposer`), all sharing one

&#x20; `renderScene = new RenderPass(scene, camera)`:

&#x20; - `torusComposer` (`renderToScreen=false`): `renderScene`, then `ShaderPass(GammaCorrectionShader)`,

&#x20;   then `new UnrealBloomPass(new THREE.Vector2(innerWidth, innerHeight), 0.22, 0.2, 0)`, then `ShaderPass(CopyShader)`.

&#x20; - `bloomComposer` (`renderToScreen=false`): `renderScene`, then

&#x20;   `new UnrealBloomPass(new THREE.Vector2(innerWidth, innerHeight), 0.4, 0.55, 0)`, then `ShaderPass(GammaCorrectionShader)`.

&#x20; - `finalComposer`: `renderScene`, then the `FinalPass` ShaderPass below.

&#x20; - Wire `finalPass.uniforms.bloomTexture.value = bloomComposer.renderTarget1.texture` and

&#x20;   `finalPass.uniforms.torusTexture.value = torusComposer.renderTarget1.texture`.

\- Helper `hexToVec3(hex)`: `const n = parseInt(hex.slice(1),16); return new THREE.Vector3(((n>>16)\&255)/255, ((n>>8)\&255)/255, (n\&255)/255)`.



\## Fixed parameters (bake these in)

```js

const CONFIG = {

&#x20; bgColor: '#0a0a24',      // dark complementary background tint

&#x20; flameColor: '#aee9ff',   // corner-flame color A

&#x20; flameColor2: '#c79bff',  // corner-flame color B

&#x20; flameAmt: 0.2,           // corner-flame intensity

&#x20; colorA: '#aef6cf',       // star tint A (mint)

&#x20; colorB: '#5fe6a0',       // star tint B (jade)

&#x20; colorC: '#eafff2',       // star tint C (bone)

&#x20; opacity: 2,

&#x20; pointSize: 50,

&#x20; brightness: 1.85,

&#x20; drift: 2.35,             // steady tunnel speed

&#x20; twinkle: 1,

&#x20; spin: 0.03,              // barrel rotation rate

&#x20; repelRadius: 5,

&#x20; repelStrength: 0.35,

&#x20; scrollPush: 8,           // forward camera dive on scroll

&#x20; scrollDrift: 6,          // extra drift surge on scroll

&#x20; scrollSpin: 0.1,         // extra spin on scroll

&#x20; parallax: 0.6,           // cursor camera offset

}

```



\## Geometry

One `THREE.Points` cloud, `count = 4200`, `depth = 30`. Build a `BufferGeometry` filling these

typed arrays in a single loop (`for i in 0..count`):



```js

positions\[i3]     = (Math.random() - 0.5) \* 24   // x: box width 24

positions\[i3 + 1] = (Math.random() - 0.5) \* 16   // y: box height 16

positions\[i3 + 2] = (Math.random() - 0.5) \* 30   // z: box depth 30 (== depth, for seamless wrap)

palette\[i] = Math.floor(Math.random() \* 3)       // 0 / 1 / 2 → tint A / B / C

bright\[i]  = 0.7 + Math.random() \* 0.6

scales\[i]  = 0.5 + Math.pow(Math.random(), 1.4) \* 2.5

phases\[i]  = Math.random()

```



Set attributes: `position` (itemSize 3), `aScale` (1), `aPhase` (1), `aPalette` (1), `aBright` (1)

— all `Float32BufferAttribute`. Wrap the points in a `THREE.Group` added to the scene, and enable

`LAYERS.ENTIRE\_SCENE` on the points object.



\## Material \& shaders

`ShaderMaterial` with `transparent: true`, `depthWrite: false`, `blending: THREE.AdditiveBlending`.



Uniforms (bake CONFIG values): `uTime:0`, `uSize: 50`, `uOpacity:0` (ramped in by the appear fade),

`uDrift:0` (accumulates), `uDepth: 30`, `uTwinkle: 1`, `uCursor: new THREE.Vector3()`,

`uRepelRadius: 5`, `uRepelStrength: 0.35`, `uActivity: 0`, `uColorA: hexToVec3('#aef6cf')`,

`uColorB: hexToVec3('#5fe6a0')`, `uColorC: hexToVec3('#eafff2')`, `uBrightness: 1.85`.



Vertex shader (verbatim):

```glsl

uniform float uTime; uniform float uSize; uniform float uDrift; uniform float uDepth; uniform float uTwinkle;

uniform vec3 uCursor; uniform float uRepelRadius; uniform float uRepelStrength; uniform float uActivity;

uniform vec3 uColorA; uniform vec3 uColorB; uniform vec3 uColorC;

attribute float aScale; attribute float aPhase; attribute float aPalette; attribute float aBright;

varying vec3 vColor; varying float vTwinkle;

void main() {

&#x20; vec3 pos = position;

&#x20; // Endless drift toward +Z with mod-wrap.

&#x20; pos.z = mod(pos.z + uDrift + (uDepth \* 0.5), uDepth) - (uDepth \* 0.5);



&#x20; float tw = sin(uTime \* 1.6 + aPhase \* 6.2831);

&#x20; vTwinkle = (1.0 - uTwinkle) + uTwinkle \* (0.55 + 0.45 \* tw);



&#x20; vec4 modelPosition = modelMatrix \* vec4(pos, 1.0);



&#x20; vec3 toParticle = modelPosition.xyz - uCursor;

&#x20; float dist = length(toParticle);

&#x20; float falloff = smoothstep(uRepelRadius, 0.0, dist);

&#x20; modelPosition.xyz += normalize(toParticle + vec3(0.0001)) \* falloff \* uRepelStrength \* uActivity;



&#x20; vec4 viewPosition = viewMatrix \* modelPosition;

&#x20; gl\_Position = projectionMatrix \* viewPosition;

&#x20; gl\_PointSize = uSize \* aScale;

&#x20; gl\_PointSize \*= (1.0 / -viewPosition.z);



&#x20; vec3 base = aPalette < 0.5 ? uColorA : (aPalette < 1.5 ? uColorB : uColorC);

&#x20; vColor = base \* aBright;

}

```



Fragment shader (verbatim):

```glsl

uniform float uOpacity; uniform float uBrightness;

varying vec3 vColor; varying float vTwinkle;

void main() {

&#x20; vec2 uv = gl\_PointCoord - 0.5;

&#x20; float d = length(uv);

&#x20; if (d > 0.5) discard;

&#x20; float strength = pow(1.0 - d \* 2.0, 4.0);

&#x20; vec3 color = mix(vec3(0.0), vColor, strength);

&#x20; gl\_FragColor = vec4(color \* uBrightness, strength \* uOpacity \* vTwinkle);

}

```



\## Atmosphere / extra layers

Composite `FinalPass` ShaderPass — adds the dark complementary background and animated corner

flames, then sums the bloom/torus/diffuse/halo textures. Uniforms:



```js

uniforms: {

&#x20; iTime:        { value: 0 },

&#x20; tDiffuse:     { value: null },

&#x20; torusTexture: { value: null },   // <- bloomComposer/torusComposer render targets wired in

&#x20; bloomTexture: { value: null },

&#x20; haloTexture:  { value: null },

&#x20; uBg:       { value: hexToVec3('#0a0a24') },

&#x20; uFlameA:   { value: hexToVec3('#aee9ff') },

&#x20; uFlameB:   { value: hexToVec3('#c79bff') },

&#x20; uFlameAmt: { value: 0.2 }

}

```



Vertex shader (verbatim):

```glsl

varying vec2 vUv; void main(){ vUv = uv; gl\_Position = vec4(position, 1.0); }

```



Fragment shader (verbatim):

```glsl

uniform float iTime; uniform sampler2D tDiffuse; uniform sampler2D bloomTexture; uniform sampler2D torusTexture; uniform sampler2D haloTexture;

uniform vec3 uBg; uniform vec3 uFlameA; uniform vec3 uFlameB; uniform float uFlameAmt;

varying vec2 vUv;

vec3 warp3d(vec3 pos, float t){ float curv=.8,a=1.9,b=0.7; pos\*=2.;

&#x20; pos.x+=curv\*sin(t+a\*pos.y)+t\*b; pos.y+=curv\*cos(t+a\*pos.x);

&#x20; pos.y+=curv\*sin(t+a\*pos.z)+t\*b; pos.z+=curv\*cos(t+a\*pos.y);

&#x20; pos.z+=curv\*sin(t+a\*pos.x)+t\*b; pos.x+=curv\*cos(t+a\*pos.z);

&#x20; return 0.5+0.5\*cos(pos.xyz+vec3(1,2,4)); }

void main(){

&#x20; vec2 uv = 2.\*vUv - 1.;

&#x20; vec3 w = pow(warp3d(vec3(uv.x, sin(uv.y), uv.y), iTime\*1.5), vec3(1.5));

&#x20; vec3 flame = 1.5\*uFlameA\*w.x; flame\*=w.y; flame += uFlameB\*w.z;

&#x20; flame \*= smoothstep(0.25, 1., abs(uv.y));

&#x20; float md = smoothstep(-0.7, 1., -uv.y\*uv.x); flame \*= md\*md;

&#x20; vec3 bg = uBg \* (1.0 - 0.4 \* length(uv));

&#x20; vec3 halo = texture2D(haloTexture, vUv).xyz;

&#x20; gl\_FragColor = vec4(bg + flame\*uFlameAmt + texture2D(bloomTexture, vUv).xyz + texture2D(torusTexture, vUv).xyz + texture2D(tDiffuse, vUv).xyz + halo, 1.);

}

```



\## Animation \& interaction



\*\*Pointer (world-space cursor "void").\*\* Track NDC on `mousemove`

(`x = clientX/innerWidth\*2-1`, `y = -(clientY/innerHeight\*2-1)`), set `active=true` and record

`lastMove`; on `mouseout` set `active=false`. Each frame: if active, unproject NDC at z=0.5,

build a ray from the camera, intersect the `z=0` plane (`t = -camera.position.z / dir.z`, valid

when `|dir.z|>1e-4`, `t>0`, finite) → world target, else target `(0,0,0)`. Lerp

`POINTER.world` toward target by `0.12`. Compute idle seconds since `lastMove`; `want = (active \&\& idle<3) ? 1 : 0`;

ease `POINTER.activity += (want - activity) \* 0.06`. Feed `POINTER.world → uCursor` and

`POINTER.activity → uActivity`.



\*\*Scroll (double-damped).\*\* On scroll, `scrollTarget = clamp(scrollY / (scrollHeight - innerHeight), 0, 1)`.

Per frame: `scrollSmooth = lerp(scrollSmooth, scrollTarget, 0.10)`,

`scrollCurrent = lerp(scrollCurrent, scrollSmooth, 0.06)`. Also smooth the pointer NDC into

`mouseSmooth.{x,y}` by `0.06` for parallax.



\*\*Per-frame scene update\*\* (`scroll = scrollCurrent`, `m = mouseSmooth`):

\- `t = performance.now()/1000`; `dt = min(0.05, t - t0)`; `t0 = t`. Set `uTime = t`.

\- `uDrift += dt \* (CONFIG.drift + scroll \* CONFIG.scrollDrift)` → `2.35 + scroll\*6`.

\- `camera.position.set(m.x \* 0.6, m.y \* 0.6, 5 - scroll \* 8)` and

&#x20; `camera.lookAt(m.x \* 0.6, m.y \* 0.6, -10)`.

\- \*\*Appear fade:\*\* `elapsed = now - appearStart`; `fade = clamp((elapsed - 300) / 1400, 0, 1)`;

&#x20; `uOpacity = fade \* 2`.

\- `group.rotation.z += dt \* (CONFIG.spin + scroll \* CONFIG.scrollSpin)` → `0.03 + scroll\*0.1`.



\*\*Render loop\*\* (`requestAnimationFrame`): set `finalPass.uniforms.iTime = performance.now()/1000`,

advance the scroll/mouse lerps and `updatePointer()`, run the scene update, then render the three

composers in order using camera layer switching:

```js

camera.layers.set(LAYERS.TORUS\_SCENE);  torusComposer.render()

camera.layers.set(LAYERS.BLOOM\_SCENE);  bloomComposer.render()

camera.layers.set(LAYERS.ENTIRE\_SCENE); finalComposer.render()

```



\*\*Resize:\*\* update renderer pixel ratio + size (`false`), `camera.aspect`,

`updateProjectionMatrix()`, and `setPixelRatio` + `setSize` on all three composers; recompute scroll.



\## Assets

None — fully procedural.



Use exactly these parameter values — do not substitute your own:



Colours:

\- bgColor: #0a0a24

\- colorA: #aef6cf

\- colorB: #5fe6a0

\- colorC: #eafff2

\- flameColor: #aee9ff

\- flameColor2: #c79bff



Settings:

\- brightness: 1.85

\- drift: 2.35

\- flameAmt: 0.2

\- opacity: 2

\- parallax: 0.6

\- pointSize: 50

\- repelRadius: 5

\- repelStrength: 0.35

\- scrollDrift: 6

\- scrollPush: 8

\- scrollSpin: 0.1

\- spin: 0.03

\- twinkle: 1
