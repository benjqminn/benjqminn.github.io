const blockSize = 20;
const cols = 16;
const rows = 16;

let currentX = 0;
let currentY = 0;
let drawingDone = false;

let tntFlash = false;
let flashCount = 0;
let flashStartTime = 0;
const FLASH_DURATION = 300;

let exploded = false;
let explosionStartTime = 0;
let shakeIntensity = 0;

function setup() {
  createCanvas(blockSize * cols, blockSize * rows);
  frameRate(60);
  noStroke();
  background(0);
}

function draw() {
    if (exploded) {
        const elapsed = millis() - explosionStartTime;

        if (elapsed < 3000) {
            shakeIntensity = map(3000 - elapsed, 0, 3000, 0, 20);
            let shakeX = random(-shakeIntensity, shakeIntensity);
            let shakeY = random(-shakeIntensity, shakeIntensity);

            push(); 
            translate(shakeX, shakeY);

            fill(255); 
            rect(0, 0, width, height);

            pop(); // End shake
        } else {
            exploded = false;
            tntFlash = false;
            drawFullFace('creeper');
        }
        return;
    }

    if (!drawingDone && currentY < rows) {
        drawBlock(currentX, currentY, 'creeper');
        currentX++;
        if (currentX >= cols) {
            currentX = 0;
            currentY++;
        }
        if (currentY >= rows) {
            drawingDone = true;
        }
        return;
    }

    if (tntFlash && millis() - flashStartTime < FLASH_DURATION) {
        background(0); 
        drawFullFace(flashCount % 2 === 0 ? 'tnt' : 'creeper');
    } else if (tntFlash && flashCount < 4) {
        flashCount++;
        flashStartTime = millis();
        background(0); 
        drawFullFace(flashCount % 2 === 0 ? 'tnt' : 'creeper');
    } else if (tntFlash && flashCount === 4) {
        flashCount++;
        explosionStartTime = millis();
        exploded = true;
    }
}

function mousePressed() {
  if (drawingDone && !tntFlash && !exploded) {
    tntFlash = true;
    flashCount = 0;
    flashStartTime = millis();
  }
}

function drawBlock(x, y, type) {
  const faceMap = getFaceMap(type);
  const cell = faceMap[y][x];

  if (type === 'creeper') {
    if (cell === 'g') fill(randomGreen());
    else if (cell === 'b') fill(0);
    else fill(0);
  }

  if (type === 'tnt') {
    if (cell === 'r') fill(255, 0, 0);
    else if (cell === 'd') fill(139, 0, 0);
    else if (cell === 'w') fill(255);
    else if (cell === 'b') fill(0);
    else fill(50);
  }

  rect(x * blockSize, y * blockSize, blockSize, blockSize);
}

function drawFullFace(type) {
  for (let y = 0; y < rows; y++) {
    for (let x = 0; x < cols; x++) {
      drawBlock(x, y, type);
    }
  }
}

function randomGreen() {
  return color(40 + random(-10, 10), 180 + random(-20, 20), 40 + random(-10, 10));
}

function getFaceMap(type) {
  if (type === 'creeper') {
    return [
      'gggggggggggggggg',
      'gggggggggggggggg',
      'gggggggggggggggg',
      'gggggggggggggggg',
      'ggbbbbggggbbbbgg',
      'ggbbbbggggbbbbgg',
      'ggbbbbggggbbbbgg',
      'ggbbbbggggbbbbgg',
      'ggggggbbbbgggggg',
      'ggggggbbbbgggggg',
      'ggggbbbbbbbbgggg',
      'ggggbbbbbbbbgggg',
      'ggggbbbbbbbbgggg',
      'ggggbbbbbbbbgggg',
      'ggggbbggggbbgggg',
      'ggggbbggggbbgggg',
    ];
  } else if (type === 'tnt') {
    return [
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd',
      'wwwwwwwwwwwwwwww',
      'wwbbbwbwwbwbbbww',
      'wwwbwwbbwbwwbwww',
      'wwwbwwbwbbwwbwww',
      'wwwbwwbwwbwwbwww',
      'wwwwwwwwwwwwwwww',
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd',
      'rrrdrrrdrrrdrrrd'
    ];
  }
}
