class WidgetTree{
    constructor({blessed = {}, contrib = {}, screen = {}, grid = {}}){
        this.blessed = blessed;
        this.contrib = contrib;
        this.screen = screen;
        this.grid = grid;
        this.parameters = { vi:true, style: {border: {fg:'magenta'}}, template: { lines: true }, label: 'default'};
        this.widget = this.getWidget();
    }

    getWidget(){
        return this.grid.gridObj.set(...this.grid.gridLayout, this.contrib.tree, this.parameters);
    }

    
}
module.exports = WidgetTree;
